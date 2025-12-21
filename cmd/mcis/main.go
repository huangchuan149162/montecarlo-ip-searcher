package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/mutou/montecarlo-ip-searcher/internal/output"
	"github.com/mutou/montecarlo-ip-searcher/internal/probe"
	"github.com/mutou/montecarlo-ip-searcher/internal/search"
)

type repeatStringFlag []string

func (r *repeatStringFlag) String() string { return strings.Join(*r, ",") }
func (r *repeatStringFlag) Set(v string) error {
	*r = append(*r, v)
	return nil
}

func main() {
	var (
		cidrs     repeatStringFlag
		cidrFile  string
		budget    int
		topN      int
		concur    int
		heads     int
		beam      int
		timeout   time.Duration
		sni       string
		hostHdr   string
		path      string
		outFmt    string
		outPath   string
		splitV4   int
		splitV6   int
		minSplit  int
		maxBitsV4 int
		maxBitsV6 int
		seed      int64
		verbose   bool
	)

	flag.Var(&cidrs, "cidr", "CIDR to search (repeatable). Example: 1.1.0.0/16 or 2606:4700::/32")
	flag.StringVar(&cidrFile, "cidr-file", "", "Path to a file containing CIDRs (one per line, # comment supported)")
	flag.IntVar(&budget, "budget", 2000, "Total probe budget (number of IPs to probe)")
	flag.IntVar(&topN, "top", 20, "Top N IPs to output")
	flag.IntVar(&concur, "concurrency", 200, "Probe concurrency")
	flag.IntVar(&heads, "heads", 4, "Number of search heads (diversification)")
	flag.IntVar(&beam, "beam", 32, "Beam width per head (kept candidate prefixes)")
	flag.DurationVar(&timeout, "timeout", 3*time.Second, "Per-probe timeout")
	flag.StringVar(&sni, "sni", "example.com", "TLS SNI server name")
	flag.StringVar(&hostHdr, "host-header", "example.com", "HTTP Host header")
	flag.StringVar(&path, "path", "/cdn-cgi/trace", "HTTP path to request")
	flag.StringVar(&outFmt, "out", "jsonl", "Output format: jsonl|csv|text")
	flag.StringVar(&outPath, "out-file", "", "Write output to file (default: stdout)")
	flag.IntVar(&splitV4, "split-step-v4", 2, "When splitting an IPv4 prefix, increase prefix bits by this step")
	flag.IntVar(&splitV6, "split-step-v6", 4, "When splitting an IPv6 prefix, increase prefix bits by this step")
	flag.IntVar(&minSplit, "min-samples-split", 20, "Minimum samples on a prefix before it can be split")
	flag.IntVar(&maxBitsV4, "max-bits-v4", 24, "Maximum IPv4 prefix bits to drill down to")
	flag.IntVar(&maxBitsV6, "max-bits-v6", 56, "Maximum IPv6 prefix bits to drill down to")
	flag.Int64Var(&seed, "seed", 0, "Random seed (0 = time-based)")
	flag.BoolVar(&verbose, "v", false, "Verbose progress to stderr")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg := search.Config{
		Budget:          budget,
		TopN:            topN,
		Concurrency:     concur,
		Heads:           heads,
		Beam:            beam,
		SplitStepV4:     splitV4,
		SplitStepV6:     splitV6,
		MinSamplesSplit: minSplit,
		MaxBitsV4:       maxBitsV4,
		MaxBitsV6:       maxBitsV6,
		Seed:            seed,
		Verbose:         verbose,
	}

	probeCfg := probe.Config{
		Timeout:    timeout,
		SNI:        sni,
		HostHeader: hostHdr,
		Path:       path,
	}

	req := search.Request{
		CIDRs:    []string(cidrs),
		CIDRFile: cidrFile,
		Probe:    probeCfg,
	}

	res, err := search.Run(ctx, cfg, req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	var w *os.File = os.Stdout
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		defer func() {
			_ = f.Close()
		}()
		w = f
	}

	switch outFmt {
	case "jsonl":
		if err := output.WriteJSONL(w, res.Top); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "csv":
		if err := output.WriteCSV(w, res.Top); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "text":
		if err := output.WriteText(w, res.Top); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "debug":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	default:
		fmt.Fprintln(os.Stderr, "error: unknown -out:", outFmt)
		os.Exit(1)
	}
}
