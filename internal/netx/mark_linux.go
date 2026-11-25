//go:build linux

package netx

import "syscall"

func setMark(fd int, mark uint32) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
}
