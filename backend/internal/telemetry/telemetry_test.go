package telemetry

import (
	"bytes"
	"errors"
	"log/slog"
	"math"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoggerForwardsImportantRecords(t *testing.T) {
	var out bytes.Buffer
	lv := new(slog.LevelVar)
	log, hub := NewLogger(&out, lv, slog.LevelWarn)
	ch, stop := hub.Subscribe()
	defer stop()

	l := log.With("component", "session").WithGroup("path")
	l.Info("quiet")
	l.Warn("path down", "id", 3, "err", errors.New("eof"))
	select {
	case r := <-ch:
		if r.Message != "path down" || r.Level != "WARN" || r.Attrs["component"] != "session" ||
			r.Attrs["path.err"] != "eof" || r.Attrs["path.id"] != int64(3) {
			t.Fatalf("record %+v", r)
		}
	case <-time.After(time.Second):
		t.Fatal("warning not forwarded")
	}
	select {
	case r := <-ch:
		t.Fatalf("info forwarded: %+v", r)
	default:
	}
	if !strings.Contains(out.String(), `"msg":"quiet"`) {
		t.Fatalf("log output %s", out.String())
	}
	lv.Set(slog.LevelError)
	log.Warn("hidden")
	if strings.Contains(out.String(), "hidden") {
		t.Fatal("level not applied")
	}
	stop()
	stop() // idempotent
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	err := WriteText(&buf, []Metric{
		{Name: "marmot_up", Help: "1 if up", Type: Gauge, Samples: []Sample{{Value: 1}}},
		{Name: "marmot_bytes_total", Help: "bytes\nmoved", Type: Counter, Samples: []Sample{
			{Labels: map[string]string{"peer": `a"b`, "dir": "in"}, Value: 1e12},
			{Labels: map[string]string{"peer": "c"}, Value: math.Inf(1)},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `# HELP marmot_up 1 if up
# TYPE marmot_up gauge
marmot_up 1
# HELP marmot_bytes_total bytes\nmoved
# TYPE marmot_bytes_total counter
marmot_bytes_total{dir="in",peer="a\"b"} 1e+12
marmot_bytes_total{peer="c"} +Inf
`
	if buf.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", buf.String(), want)
	}
	rec := httptest.NewRecorder()
	Handler(func() []Metric { return nil }).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	if formatValue(math.NaN()) != "NaN" || formatValue(math.Inf(-1)) != "-Inf" {
		t.Fatal("special values")
	}
}

func TestReadCgroupLimit(t *testing.T) {
	dir := t.TempDir()
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		_ = os.WriteFile(p, []byte(v), 0o600)
		return p
	}
	if v := readCgroupLimit([]string{write("v2", "536870912\n")}); v != 512<<20 {
		t.Fatalf("v2 %d", v)
	}
	if v := readCgroupLimit([]string{write("max", "max\n")}); v != 0 {
		t.Fatalf("max %d", v)
	}
	if v := readCgroupLimit([]string{write("v1", "9223372036854771712")}); v != 0 {
		t.Fatalf("v1 unlimited %d", v)
	}
	if v := readCgroupLimit([]string{filepath.Join(dir, "missing"), write("b", "1048576")}); v != 1<<20 {
		t.Fatalf("fallback %d", v)
	}
	t.Setenv("GOMEMLIMIT", "1GiB")
	if ApplyMemoryLimit() != 0 {
		t.Fatal("explicit GOMEMLIMIT overridden")
	}
}
