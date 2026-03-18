// Package runner executes a guest binary against binary block input and
// parses the JSON result line written to stdout.
//
// Guest contract:
//   - stdin:  binary StatelessInput (pipeline.Fetch output)
//   - stdout: one JSON line: {"block":N,"valid":true,"pre_state_root":"0x...","post_state_root":"0x...","receipts_root":"0x..."}
//   - stderr: informational (logged but not parsed)
package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Gabriel-Trintinalia/stateless-executor/metrics"
	"github.com/Gabriel-Trintinalia/stateless-executor/store"
)

// GuestSpec identifies a guest binary by name and filesystem path.
type GuestSpec struct {
	Name string
	Path string
}

// ParseGuestSpecs parses the GUEST_BINARIES env var value.
// Format: "name:/path/to/binary,name2:/path/to/binary2"
func ParseGuestSpecs(s string) ([]GuestSpec, error) {
	var specs []GuestSpec
	for _, entry := range strings.Split(s, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		idx := strings.Index(entry, ":")
		if idx < 0 {
			return nil, fmt.Errorf("invalid GUEST_BINARIES entry %q: expected name:/path", entry)
		}
		specs = append(specs, GuestSpec{
			Name: entry[:idx],
			Path: entry[idx+1:],
		})
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("GUEST_BINARIES is empty")
	}
	return specs, nil
}

// guestResult is the JSON emitted by the guest to stdout.
type guestResult struct {
	Block                  uint64 `json:"block"`
	Valid                  bool   `json:"valid"`                   // legacy single-line format
	SuccessfulValidation   bool   `json:"successful_validation"`   // zevm-stateless format
}

// Run executes the guest binary at spec.Path, feeding input via stdin, and
// returns a store.Result ready to be added to the ring buffer.
//
// forkName is optional (e.g. "cancun"); if non-empty it is passed as --fork.
func Run(ctx context.Context, spec GuestSpec, input []byte, forkName string) (store.Result, error) {
	// Ensure the binary is executable (Kurtosis file artifacts may drop the bit).
	if err := os.Chmod(spec.Path, 0755); err != nil {
		log.Printf("runner [%s]: chmod %s: %v (continuing)", spec.Name, spec.Path, err)
	}

	start := time.Now()

	args := []string{}
	if forkName != "" {
		args = append(args, "--fork", forkName)
	}

	cmd := exec.CommandContext(ctx, spec.Path, args...)
	cmd.Stdin = bytes.NewReader(input)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	durationMs := time.Since(start).Milliseconds()

	logOutput := strings.TrimSpace(stderr.String())
	if logOutput != "" {
		log.Printf("runner [%s]: %s", spec.Name, logOutput)
	}

	if err != nil {
		metrics.BlockVerifiedTotal.WithLabelValues(spec.Name, "error").Inc()
		metrics.VerificationDurationMs.WithLabelValues(spec.Name).Observe(float64(durationMs))
		return store.Result{Log: logOutput}, fmt.Errorf("runner [%s]: %w", spec.Name, err)
	}

	line, parseErr := lastJSONLine(stdout.Bytes())
	if parseErr != nil {
		metrics.BlockVerifiedTotal.WithLabelValues(spec.Name, "error").Inc()
		metrics.VerificationDurationMs.WithLabelValues(spec.Name).Observe(float64(durationMs))
		return store.Result{Log: logOutput}, fmt.Errorf("runner [%s]:   parsing output: %w (stdout=%q)", spec.Name, parseErr, stdout.String())
	}

	result := "ok"
	if !line.Valid && !line.SuccessfulValidation {
		result = "fail"
	}
	metrics.BlockVerifiedTotal.WithLabelValues(spec.Name, result).Inc()
	metrics.VerificationDurationMs.WithLabelValues(spec.Name).Observe(float64(durationMs))

	return store.Result{
		Block:      line.Block,
		Guest:      spec.Name,
		Valid:      line.Valid || line.SuccessfulValidation,
		Log:        logOutput,
		DurationMs: durationMs,
	}, nil
}

// lastJSONLine parses a guestResult from stdout.
// It first tries the full buffer (handles pretty-printed multi-line JSON),
// then falls back to scanning backwards line-by-line (handles single-line JSON
// with trailing log output).
func lastJSONLine(buf []byte) (guestResult, error) {
	trimmed := bytes.TrimSpace(buf)
	if len(trimmed) == 0 {
		return guestResult{}, io.EOF
	}
	// Fast path: whole buffer is valid JSON.
	var r guestResult
	if err := json.Unmarshal(trimmed, &r); err == nil {
		return r, nil
	}
	// Fallback: scan backwards for the last line that parses as JSON.
	lines := bytes.Split(trimmed, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		if err := json.Unmarshal(line, &r); err != nil {
			return guestResult{}, fmt.Errorf("invalid JSON %q: %w", line, err)
		}
		return r, nil
	}
	return guestResult{}, io.EOF
}
