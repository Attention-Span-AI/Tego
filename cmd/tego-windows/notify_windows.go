// SPDX-License-Identifier: Apache-2.0

package main

import (
	"golang.org/x/sys/windows"
	"runtime"
	"unsafe"
)

// A registry write alone leaves Explorer's environment stale. Broadcast from
// the already verified native command, without adding a persistent type or
// function to the installer's interactive PowerShell session.
func pathChanged() int {
	name, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return 125
	}
	var result uintptr
	send := windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")
	ok, _, _ := send.Call(0xffff, 0x001a, 0, uintptr(unsafe.Pointer(name)), 0x0002, 5000, uintptr(unsafe.Pointer(&result)))
	runtime.KeepAlive(name)
	if ok == 0 {
		return 125
	}
	return 0
}
