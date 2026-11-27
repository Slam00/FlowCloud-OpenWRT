//go:build linux

package zapret

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// killStray ends instances of binary left on the queue argument by a daemon
// that died before it could stop them (SIGKILL, a crash): the orphan keeps
// the queue, and the next nfqws2 fails with "nfq_create_queue(): Operation
// not permitted". Pdeathsig cannot do this: nfqws2 drops privileges, which
// clears it.
func killStray(binary, queueArgument string) {
	processes, _ := filepath.Glob("/proc/[0-9]*/cmdline")
	for _, path := range processes {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		fields := bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0})
		if len(fields) == 0 || string(fields[0]) != binary {
			continue
		}
		for _, field := range fields[1:] {
			if string(field) != queueArgument {
				continue
			}
			pid, err := strconv.Atoi(filepath.Base(filepath.Dir(path)))
			if err == nil && pid != os.Getpid() {
				log.Printf("zapret: stopping nfqws2 %d left by a previous run", pid)
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
			break
		}
	}
}
