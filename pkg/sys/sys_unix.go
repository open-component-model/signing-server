//go:build unix

package sys

import (
	. "syscall"
)

func Detach() error {
	_, _, err := Syscall(SYS_IOCTL, 0, uintptr(TIOCNOTTY), 0)
	if err != 0 {
		return err
	}
	_, _, err = Syscall(SYS_SETPGID, 0, uintptr(0), 0)
	if err != 0 {
		return err
	}
	return nil
}
