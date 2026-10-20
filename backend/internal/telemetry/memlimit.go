package telemetry

import (
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// memLimitShare is the part of the container's memory limit given to the
// Go heap; the rest is headroom for stacks, buffers outside the heap and
// the kernel's socket memory accounted to the cgroup.
const memLimitShare = 0.9

// cgroupMemoryFiles are where cgroup v2 and v1 publish the memory limit.
var cgroupMemoryFiles = []string{
	"/sys/fs/cgroup/memory.max",
	"/sys/fs/cgroup/memory/memory.limit_in_bytes",
}

// ApplyMemoryLimit sets the Go soft memory limit from the container's
// cgroup limit, unless GOMEMLIMIT is set explicitly. It returns the limit
// applied, or 0 when none was found. GOGC is read by the runtime itself.
func ApplyMemoryLimit() int64 {
	if os.Getenv("GOMEMLIMIT") != "" {
		return 0
	}
	limit := readCgroupLimit(cgroupMemoryFiles)
	if limit <= 0 {
		return 0
	}
	v := int64(float64(limit) * memLimitShare)
	debug.SetMemoryLimit(v)
	return v
}

// readCgroupLimit returns the first finite limit found, or 0.
func readCgroupLimit(files []string) int64 {
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(b))
		if s == "max" {
			return 0
		}
		v, err := strconv.ParseInt(s, 10, 64)
		// cgroup v1 reports "no limit" as a huge number near MaxInt64.
		if err != nil || v <= 0 || v > 1<<60 {
			return 0
		}
		return v
	}
	return 0
}
