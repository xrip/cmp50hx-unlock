package hxcore

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SetFb20gVar writes ("20G") or deletes the 50HXFB firmware variable — the
// Windows channel for the fb=20g override (issue #39). bcdedit firmware
// boot entries cannot carry LoadOptions, so the unlock EFI also accepts
// this variable; Linux uses the plain efibootmgr -u "fb=20g" token.
// "20G" forces 20 GiB geometry on modified 20 GB cards whose POST-latched
// WPR2 mis-reports the size; no variable keeps the WPR2 heuristic.
func SetFb20gVar(on bool) error {
	// An elevated admin token still carries SeSystemEnvironmentPrivilege
	// DISABLED by default — without this explicit enable the variable
	// write fails with "A required privilege is not held by the client"
	// (issue #39, confirmed on a real host even when run as administrator).
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil,
		windows.StringToUTF16Ptr("SeSystemEnvironmentPrivilege"), &luid); err != nil {
		return fmt.Errorf("LookupPrivilegeValue: %w", err)
	}
	tok, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer tok.Close()
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0].Luid = luid
	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
		return fmt.Errorf("AdjustTokenPrivileges: %w", err)
	}

	k32 := syscall.NewLazyDLL("kernel32.dll")
	pSet := k32.NewProc("SetFirmwareEnvironmentVariableExW")
	var (
		val  uintptr
		sz   uint32
		attr uint32 // attributes=0 + size=0 deletes (EFI SetVariable semantics)
	)
	if on {
		v := []uint16{'2', '0', 'G', 0}
		val = uintptr(unsafe.Pointer(&v[0]))
		sz = uint32(len(v) * 2)
		attr = 7 // EFI_VARIABLE_NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS
	}
	r, _, err := pSet.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("50HXFB"))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("{8be4df61-93ca-11d2-aa0d-00e098032b8c}"))),
		val, uintptr(sz), uintptr(attr))
	if r == 0 {
		return err
	}
	return nil
}
