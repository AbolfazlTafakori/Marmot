package telemetry

import (
	"bufio"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// Metric types of the Prometheus text format.
const (
	Gauge   = "gauge"
	Counter = "counter"
)

// Metric is one metric family with its samples.
type Metric struct {
	Name    string
	Help    string
	Type    string
	Samples []Sample
}

// Sample is one labelled value.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// WriteText writes metrics in the Prometheus text exposition format 0.0.4.
func WriteText(w io.Writer, metrics []Metric) error {
	bw := bufio.NewWriter(w)
	for _, m := range metrics {
		bw.WriteString("# HELP " + m.Name + " " + escapeHelp(m.Help) + "\n")
		bw.WriteString("# TYPE " + m.Name + " " + m.Type + "\n")
		for _, s := range m.Samples {
			bw.WriteString(m.Name)
			writeLabels(bw, s.Labels)
			bw.WriteByte(' ')
			bw.WriteString(formatValue(s.Value))
			bw.WriteByte('\n')
		}
	}
	return bw.Flush()
}

func writeLabels(bw *bufio.Writer, labels map[string]string) {
	if len(labels) == 0 {
		return
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	bw.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			bw.WriteByte(',')
		}
		bw.WriteString(k)
		bw.WriteString(`="`)
		bw.WriteString(escapeLabel(labels[k]))
		bw.WriteByte('"')
	}
	bw.WriteByte('}')
}

var (
	helpEscaper  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	labelEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
)

func escapeHelp(s string) string  { return helpEscaper.Replace(s) }
func escapeLabel(s string) string { return labelEscaper.Replace(s) }

func formatValue(v float64) string {
	switch {
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.IsNaN(v):
		return "NaN"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Handler serves the metrics returned by collect on each scrape.
func Handler(collect func() []Metric) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = WriteText(w, collect())
	})
}
