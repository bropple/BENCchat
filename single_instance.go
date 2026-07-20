package main

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
)

// Single-instance enforcement.
//
// Two copies of BENCchat on one machine fight over things that assume they are
// alone: the same config file, the same history and trust files, and — worst —
// the same device key, so both publish and each overwrites the other's device
// list. It is easy to do by accident on Windows, where launching from Explorer
// gives no hint that a copy is already running.
//
// A loopback listener rather than a lock file, because it cannot go stale. A
// lock file survives a crash and then blocks every future launch until someone
// deletes it by hand; a socket is released by the kernel the moment the process
// dies, however it died.
const singleInstancePort = 47821

var instanceLock net.Listener

// claimSingleInstance reports whether this process is the only BENCchat running.
//
// It holds the listener for the life of the process. Nothing ever connects to
// it — binding IS the claim.
func claimSingleInstance() bool {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", singleInstancePort))
	if err != nil {
		return false
	}
	instanceLock = ln
	return true
}

// notifyAlreadyRunning tells the user why nothing happened.
//
// Best-effort and deliberately dependency-free: this runs before Wails is up,
// so there is no window to attach a dialog to. On Windows a GUI build has no
// console at all, so a message box is the only thing a user double-clicking the
// icon would ever see.
func notifyAlreadyRunning() {
	if runtime.GOOS != "windows" {
		return
	}
	// Fire and forget. If this fails the worst case is the silent exit we had
	// before, which is no worse than not trying.
	_ = exec.Command("cmd", "/c",
		`echo msgbox "BENCchat is already running.",64,"BENCchat" > "%TEMP%\benchat-running.vbs" `+
			`& wscript "%TEMP%\benchat-running.vbs" & del "%TEMP%\benchat-running.vbs"`).Start()
}
