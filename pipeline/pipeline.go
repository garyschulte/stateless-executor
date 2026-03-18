// Package pipeline fetches a block and its execution witness from an EL node
// and encodes them into the format expected by zevm-stateless guests.
//
// RLP binary layout (all integers big-endian, from src/io.zig):
//
//	[u64: block_rlp_len] [block_rlp_bytes]
//	[u64: state_count]   ( [u64: len] [bytes] ) * state_count
//	[u64: codes_count]   ( [u64: len] [bytes] ) * codes_count
//	[u64: keys_count]    ( [u64: len] [bytes] ) * keys_count
//	[u64: headers_count] ( [u64: len] [bytes] ) * headers_count
//	[u64: chain_id]
//	[u64: public_keys_count] ( [u64: len] [bytes] ) * public_keys_count
//
// SSZ layout: 7-field container (fixed part = 32 bytes):
//
//	block_rlp   : offset u32 LE
//	state       : offset u32 LE
//	codes       : offset u32 LE
//	keys        : offset u32 LE
//	headers     : offset u32 LE
//	chain_id    : u64 LE  (inline fixed field)
//	public_keys : offset u32 LE
//
// Variable fields (block_rlp, state, codes, keys, headers, public_keys) follow
// the fixed part; List[Bytes] fields use 4-byte LE offset tables per SSZ spec.
//
// JSON layout: { "block_rlp": "0x...", "state": ["0x..."], ..., "public_keys": [] }
package pipeline

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/Gabriel-Trintinalia/stateless-executor/pool"
)

// Format specifies how the guest input is encoded.
type Format int

const (
	FormatRLP  Format = iota // custom big-endian length-prefixed binary (default)
	FormatSSZ                // SSZ container encoding
	FormatJSON               // JSON with 0x-hex fields
)

// ParseFormat converts a string flag value into a Format.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "rlp":
		return FormatRLP, nil
	case "", "ssz":
		return FormatSSZ, nil
	case "json":
		return FormatJSON, nil
	default:
		return 0, fmt.Errorf("unknown format %q: must be rlp, ssz, or json", s)
	}
}

// BlockMeta holds lightweight block metadata derived from the fetched block RLP.
type BlockMeta struct {
	TxCount int
	GasUsed uint64
}

// witness mirrors the JSON returned by debug_executionWitness.
type witness struct {
	State   []string        `json:"state"`
	Codes   []string        `json:"codes"`
	Keys    []string        `json:"keys"`
	Headers json.RawMessage `json:"headers"` // []string (hex) or []object depending on client
}

// Fetch retrieves the block RLP and witness for blockNum, encodes them using
// the requested format, and returns the encoded bytes, the EL node hostname
// that served the witness, and lightweight block metadata.
func Fetch(ctx context.Context, p *pool.Pool, blockNum uint64, format Format) ([]byte, string, BlockMeta, error) {
	rawURL := p.Pick()
	if rawURL == "" {
		return nil, "", BlockMeta{}, fmt.Errorf("pipeline: no healthy EL node available")
	}
	elNode := hostname(rawURL)

	hexNum := "0x" + strconv.FormatUint(blockNum, 16)

	// Fetch raw block RLP.
	rawBlockResult, err := p.CallRaw(ctx, rawURL, "debug_getRawBlock", []interface{}{hexNum})
	if err != nil {
		return nil, elNode, BlockMeta{}, fmt.Errorf("pipeline: debug_getRawBlock(%d): %w", blockNum, err)
	}
	blockRLP, err := decodeHexResult(rawBlockResult)
	if err != nil {
		return nil, elNode, BlockMeta{}, fmt.Errorf("pipeline: decoding block RLP: %w", err)
	}

	// Decode block RLP to extract metadata.
	var meta BlockMeta
	var block types.Block
	if err := rlp.DecodeBytes(blockRLP, &block); err == nil {
		meta.TxCount = block.Transactions().Len()
		meta.GasUsed = block.GasUsed()
	}

	// Fetch execution witness.
	witnessResult, err := p.CallRaw(ctx, rawURL, "debug_executionWitness", []interface{}{hexNum})
	if err != nil {
		return nil, elNode, meta, fmt.Errorf("pipeline: debug_executionWitness(%d): %w", blockNum, err)
	}
	var w witness
	if err := json.Unmarshal(witnessResult, &w); err != nil {
		return nil, elNode, meta, fmt.Errorf("pipeline: decoding witness JSON: %w", err)
	}

	// Decode headers: reth/besu return []hex-string; geth returns []header-object.
	// Both are normalised to [][]byte (RLP-encoded headers).
	headers, err := decodeHeaders(w.Headers)
	if err != nil {
		return nil, elNode, meta, fmt.Errorf("pipeline: decoding headers: %w", err)
	}

	log.Printf("block #%d [%s]: witness state=%d codes=%d keys=%d headers=%d",
		blockNum, elNode, len(w.State), len(w.Codes), len(w.Keys), len(headers))

	var encoded []byte
	switch format {
	case FormatSSZ:
		encoded, err = encodeSSZ(blockRLP, w, headers)
	case FormatJSON:
		encoded, err = encodeJSON(blockRLP, w, headers)
	default:
		encoded, err = encodeRLP(blockRLP, w, headers)
	}
	if err != nil {
		return nil, elNode, meta, err
	}

	if format == FormatJSON {
		log.Printf("block #%d [%s]: raw witness: %s", blockNum, elNode, encoded)
	} else {
		log.Printf("block #%d [%s]: raw witness: (raw %x)", blockNum, elNode, encoded)
	}
	return encoded, elNode, meta, nil
}

// encodeRLP serialises blockRLP + witness into the custom big-endian
// length-prefixed binary format expected by the RLP guest variant.
func encodeRLP(blockRLP []byte, w witness, headers [][]byte) ([]byte, error) {
	var buf bytes.Buffer

	// [u64: block_rlp_len] [block_rlp_bytes]
	if err := writeUint64(&buf, uint64(len(blockRLP))); err != nil {
		return nil, err
	}
	buf.Write(blockRLP)

	// Three hex-string arrays: state, codes, keys.
	for _, arr := range [][]string{w.State, w.Codes, w.Keys} {
		decoded, err := decodeHexArray(arr)
		if err != nil {
			return nil, err
		}
		if err := writeArray(&buf, decoded); err != nil {
			return nil, err
		}
	}

	// Headers (already decoded).
	if err := writeArray(&buf, headers); err != nil {
		return nil, err
	}

	// [u64: chain_id] — mainnet
	if err := writeUint64(&buf, 1); err != nil {
		return nil, err
	}

	// [u64: public_keys_count=0] — empty; populated by zkVM via ecrecover
	if err := writeUint64(&buf, 0); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// encodeSSZ serialises blockRLP + witness as an SSZ Container with the
// 7-field layout expected by zevm-stateless io_ssz.zig.
//
// Fixed part (32 bytes):
//
//	5 × u32 LE offsets (block_rlp, state, codes, keys, headers)
//	u64 LE chain_id  (inline fixed field)
//	u32 LE offset    (public_keys)
func encodeSSZ(blockRLP []byte, w witness, headers [][]byte) ([]byte, error) {
	state, err := decodeHexArray(w.State)
	if err != nil {
		return nil, err
	}
	codes, err := decodeHexArray(w.Codes)
	if err != nil {
		return nil, err
	}
	keys, err := decodeHexArray(w.Keys)
	if err != nil {
		return nil, err
	}

	stateBytes := sszBytesList(state)
	codesBytes := sszBytesList(codes)
	keysBytes := sszBytesList(keys)
	headersBytes := sszBytesList(headers)
	// public_keys is empty — populated by zkVM via ecrecover; empty List[Bytes] = zero bytes.

	// Fixed part: 5 offsets (4B each) + chain_id u64 (8B) + 1 offset (4B) = 32 bytes.
	const fixedSize = uint32(5*4 + 8 + 4)

	blockRLPOffset := fixedSize
	stateOffset := blockRLPOffset + uint32(len(blockRLP))
	codesOffset := stateOffset + uint32(len(stateBytes))
	keysOffset := codesOffset + uint32(len(codesBytes))
	headersOffset := keysOffset + uint32(len(keysBytes))
	publicKeysOffset := headersOffset + uint32(len(headersBytes))

	var buf bytes.Buffer
	writeU32LE(&buf, blockRLPOffset)
	writeU32LE(&buf, stateOffset)
	writeU32LE(&buf, codesOffset)
	writeU32LE(&buf, keysOffset)
	writeU32LE(&buf, headersOffset)
	writeU64LE(&buf, 1) // chain_id = mainnet
	writeU32LE(&buf, publicKeysOffset)

	buf.Write(blockRLP)
	buf.Write(stateBytes)
	buf.Write(codesBytes)
	buf.Write(keysBytes)
	buf.Write(headersBytes)
	// public_keys: empty — write nothing

	return buf.Bytes(), nil
}

// sszBytesList serialises a List[bytes] (variable-length elements) per the SSZ
// spec: a 4-byte LE offset table followed by the concatenated element bytes.
func sszBytesList(items [][]byte) []byte {
	if len(items) == 0 {
		return nil
	}
	fixedSize := uint32(4 * len(items))
	offset := fixedSize
	var buf bytes.Buffer
	for _, item := range items {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], offset)
		buf.Write(b[:])
		offset += uint32(len(item))
	}
	for _, item := range items {
		buf.Write(item)
	}
	return buf.Bytes()
}

// jsonWitnessInput is the JSON representation of the guest input.
type jsonWitnessInput struct {
	BlockRLP   string   `json:"block_rlp"`
	State      []string `json:"state"`
	Codes      []string `json:"codes"`
	Keys       []string `json:"keys"`
	Headers    []string `json:"headers"`
	PublicKeys []string `json:"public_keys"`
}

// encodeJSON serialises blockRLP + witness as a JSON object with 0x-hex fields.
// State, Codes, and Keys pass through the hex strings from the witness verbatim;
// headers are re-encoded as 0x-hex. PublicKeys is always empty (populated by zkVM).
func encodeJSON(blockRLP []byte, w witness, headers [][]byte) ([]byte, error) {
	headersHex := make([]string, len(headers))
	for i, h := range headers {
		headersHex[i] = "0x" + hex.EncodeToString(h)
	}
	input := jsonWitnessInput{
		BlockRLP:   "0x" + hex.EncodeToString(blockRLP),
		State:      w.State,
		Codes:      w.Codes,
		Keys:       w.Keys,
		Headers:    headersHex,
		PublicKeys: []string{},
	}
	return json.Marshal(input)
}

// decodeHeaders parses the headers field from debug_executionWitness.
// Reth/besu return []hex-string (RLP-encoded); geth returns []header-object.
// Both are normalised to raw RLP bytes.
func decodeHeaders(raw json.RawMessage) ([][]byte, error) {
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "[]" {
		return nil, nil
	}
	// Reth/besu format: []hex-string, each already RLP-encoded.
	var hexStrs []string
	if err := json.Unmarshal(raw, &hexStrs); err == nil {
		return decodeHexArray(hexStrs)
	}
	// Geth format: []header-object — unmarshal and RLP-encode each one.
	var headers []*types.Header
	if err := json.Unmarshal(raw, &headers); err != nil {
		return nil, fmt.Errorf("unrecognised headers format: %w", err)
	}
	out := make([][]byte, len(headers))
	for i, h := range headers {
		b, err := rlp.EncodeToBytes(h)
		if err != nil {
			return nil, fmt.Errorf("RLP-encoding header %d: %w", i, err)
		}
		out[i] = b
	}
	return out, nil
}

// writeArray writes [u64 count] followed by [u64 len][bytes] for each element.
func writeArray(buf *bytes.Buffer, items [][]byte) error {
	if err := writeUint64(buf, uint64(len(items))); err != nil {
		return err
	}
	for _, item := range items {
		if err := writeUint64(buf, uint64(len(item))); err != nil {
			return err
		}
		buf.Write(item)
	}
	return nil
}

func writeUint64(buf *bytes.Buffer, v uint64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	_, err := buf.Write(b[:])
	return err
}

func writeU32LE(buf *bytes.Buffer, v uint32) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	buf.Write(b[:])
}

func writeU64LE(buf *bytes.Buffer, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	buf.Write(b[:])
}

// decodeHexResult unmarshals a JSON string like "\"0x...\"" into raw bytes.
func decodeHexResult(raw json.RawMessage) ([]byte, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return hexToBytes(s)
}

// decodeHexArray decodes a []string of 0x-prefixed hex values into [][]byte.
func decodeHexArray(arr []string) ([][]byte, error) {
	out := make([][]byte, len(arr))
	for i, s := range arr {
		b, err := hexToBytes(s)
		if err != nil {
			return nil, fmt.Errorf("element %d: %w", i, err)
		}
		out[i] = b
	}
	return out, nil
}

func hexToBytes(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s)%2 != 0 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

// hostname extracts the host portion from a URL (e.g. "http://el-2-geth:8545" → "el-2-geth").
func hostname(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Hostname()
}
