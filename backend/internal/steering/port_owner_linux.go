//go:build linux

package steering

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// portOwner names the process that holds port, as "nginx (pid 812)", or
// returns "" when it cannot tell (for example without permission to read
// other processes' file descriptors).
func portOwner(port uint16) string {
	inodes := socketInodes(port)
	if len(inodes) == 0 {
		return ""
	}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return ""
	}
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		procDir := "/proc/" + p.Name()
		fdDir := procDir + "/fd"
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := strings.CutPrefix(link, "socket:[")
			if !ok || !inodes[strings.TrimSuffix(inode, "]")] {
				continue
			}
			comm, _ := os.ReadFile(procDir + "/comm")
			return fmt.Sprintf("%s (pid %d)", strings.TrimSpace(string(comm)), pid)
		}
	}
	return ""
}

// socketInodes returns the inodes of TCP listeners and UDP sockets bound
// to port, from /proc/net.
func socketInodes(port uint16) map[string]bool {
	want := fmt.Sprintf(":%04X", port)
	out := map[string]bool{}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open("/proc/net/" + name)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Scan() // header
		for sc.Scan() {
			// sl local rem st tx:rx tr:when retrnsmt uid timeout inode
			fields := strings.Fields(sc.Text())
			if len(fields) < 10 || !strings.HasSuffix(fields[1], want) {
				continue
			}
			if strings.HasPrefix(name, "tcp") && fields[3] != "0A" { // LISTEN
				continue
			}
			out[fields[9]] = true
		}
		_ = f.Close()
	}
	return out
}
