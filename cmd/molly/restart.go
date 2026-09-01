package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// restartSelf relaunches the current binary with the same arguments.
// On Unix it replaces the process via syscall.Exec; on Windows it spawns
// a child process and exits, since syscall.Exec is not supported there.
func restartSelf() error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command(execPath, os.Args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("start new process: %w", err)
		}
		os.Exit(0)
		return nil
	}

	if err := syscall.Exec(execPath, os.Args, os.Environ()); err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	return nil
}
