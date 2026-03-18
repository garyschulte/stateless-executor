package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Gabriel-Trintinalia/stateless-executor/metrics"
	"github.com/Gabriel-Trintinalia/stateless-executor/pipeline"
	"github.com/Gabriel-Trintinalia/stateless-executor/pool"
	"github.com/Gabriel-Trintinalia/stateless-executor/runner"
	"github.com/Gabriel-Trintinalia/stateless-executor/store"
)

func main() {
	// ── Flags ──────────────────────────────────────────────────────────────────
	var formatStr string
	flag.StringVar(&formatStr, "format", "ssz", "guest input encoding: rlp, ssz, or json")
	flag.StringVar(&formatStr, "f", "ssz", "guest input encoding (shorthand for --format)")
	flag.Parse()

	format, err := pipeline.ParseFormat(formatStr)
	if err != nil {
		log.Fatalf("--format: %v", err)
	}

	// ── Config from environment ────────────────────────────────────────────────
	elURLs := splitEnv("EL_RPC_URLS")
	forkName := os.Getenv("FORK_NAME")
	listenAddr := envOr("LISTEN_ADDR", ":8080")

	if len(elURLs) == 0 {
		log.Fatal("EL_RPC_URLS is required (comma-separated list of RPC endpoints)")
	}

	guests, err := runner.ParseGuestSpecs(os.Getenv("GUEST_BINARIES"))
	if err != nil {
		log.Fatalf("GUEST_BINARIES: %v", err)
	}

	log.Printf("EL nodes: %v", elURLs)
	for _, g := range guests {
		log.Printf("guest:    %s → %s", g.Name, g.Path)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// ── EL pool ────────────────────────────────────────────────────────────────
	p, err := pool.New(elURLs)
	if err != nil {
		log.Fatalf("pool init: %v", err)
	}
	go p.Run(ctx)

	// ── Ring buffer ────────────────────────────────────────────────────────────
	buf := &store.RingBuffer{}

	// ── HTTP server ────────────────────────────────────────────────────────────
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/results", buf.Handler())

	srv := &http.Server{Addr: listenAddr, Handler: mux}
	go func() {
		log.Printf("HTTP server listening on %s", listenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server: %v", err)
		}
	}()

	// ── Block pipeline ─────────────────────────────────────────────────────────
	log.Println("Waiting for new block heads...")
	for {
		select {
		case <-ctx.Done():
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = srv.Shutdown(shutdownCtx)
			return

		case blockNum := <-p.Heads:
			metrics.BlockHeight.Set(float64(blockNum))
			log.Printf("block #%d: fetching", blockNum)

			fetchCtx, fetchCancel := context.WithTimeout(ctx, 30*time.Second)
			input, elNode, meta, err := pipeline.Fetch(fetchCtx, p, blockNum, format)
			fetchCancel()
			if err != nil {
				log.Printf("block #%d: fetch error: %v", blockNum, err)
				continue
			}
			log.Printf("block #%d: encoded %d bytes from %s, fanning out to %d guest(s)", blockNum, len(input), elNode, len(guests))

			var wg sync.WaitGroup
			for _, g := range guests {
				wg.Add(1)
				go func(spec runner.GuestSpec) {
					defer wg.Done()
					runCtx, runCancel := context.WithTimeout(ctx, 5*time.Minute)
					defer runCancel()

					result, err := runner.Run(runCtx, spec, input, forkName)
					result.WitnessFrom = elNode
					result.TxCount = meta.TxCount
					result.GasUsed = meta.GasUsed
					if err != nil {
						result.Block = blockNum
						result.Guest = spec.Name
						result.Error = err.Error()
						log.Printf("block #%d [%s]: runner error: %v", blockNum, spec.Name, err)
					}
					buf.Add(result)
					if result.Valid {
						log.Printf("block #%d [%s]: OK (%dms)", blockNum, spec.Name, result.DurationMs)
					} else {
						log.Printf("block #%d [%s]: FAIL (%dms)", blockNum, spec.Name, result.DurationMs)
					}
				}(g)
			}
			wg.Wait()
		}
	}
}

func splitEnv(key string) []string {
	val := os.Getenv(key)
	if val == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(val, ",") {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
