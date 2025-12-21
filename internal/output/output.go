package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/mutou/montecarlo-ip-searcher/internal/search"
)

func WriteJSONL(w io.Writer, rows []search.TopResult) error {
	enc := json.NewEncoder(w)
	for _, r := range rows {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}

func WriteCSV(w io.Writer, rows []search.TopResult) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{
		"rank", "ip", "prefix",
		"ok", "status",
		"connect_ms", "tls_ms", "ttfb_ms", "total_ms",
		"score_ms", "samples_prefix", "ok_prefix", "fail_prefix",
		"colo",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for i, r := range rows {
		colo := ""
		if r.Trace != nil {
			colo = r.Trace["colo"]
		}
		rec := []string{
			strconv.Itoa(i + 1),
			r.IP.String(),
			r.Prefix.String(),
			strconv.FormatBool(r.OK),
			strconv.Itoa(r.Status),
			strconv.FormatInt(r.ConnectMS, 10),
			strconv.FormatInt(r.TLSMS, 10),
			strconv.FormatInt(r.TTFBMS, 10),
			strconv.FormatInt(r.TotalMS, 10),
			fmt.Sprintf("%.2f", r.ScoreMS),
			strconv.Itoa(r.PrefixSamples),
			strconv.Itoa(r.PrefixOK),
			strconv.Itoa(r.PrefixFail),
			colo,
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func WriteText(w io.Writer, rows []search.TopResult) error {
	// Ensure stable output.
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].ScoreMS < rows[j].ScoreMS })
	for i, r := range rows {
		colo := ""
		if r.Trace != nil {
			colo = r.Trace["colo"]
		}
		_, err := fmt.Fprintf(w, "%d\t%s\t%.1fms\tok=%v\tstatus=%d\tprefix=%s\tcolo=%s\n",
			i+1, r.IP.String(), r.ScoreMS, r.OK, r.Status, r.Prefix.String(), colo)
		if err != nil {
			return err
		}
	}
	return nil
}
