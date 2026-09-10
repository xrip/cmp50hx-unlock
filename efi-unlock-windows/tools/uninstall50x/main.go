// 50HX one-click uninstaller v3.0.0 (CMP 50HX Windows Unlock Uninstaller)
// GUI no-console build: double-clicking does not pop a console; output
// goes to %TEMP%\50HX_uninstaller.log and a message box is shown at exit.
// Removes: scheduled tasks (including the Gen2 retry task) / Gen2 Run
// key / firmware boot entry "50HX Unlock"
//
//	/ ESP unlock EFI (with \EFI\Boot\bootx64.efi fallback copy and .bak
//	  restore) / driver services and files / EnableGpuFirmware (restores
//	  GSP to its default off state).
//
// v2.6.0: all cleanup implementations lifted into 50hxcore/uninstall_ops.go
// — shared with the installer GUI's component-level uninstall,
// eliminating the two drifting copies. This file only keeps the
// orchestration and interaction.
// Power settings (Fast Startup / ASPM) are NOT rolled back — they are
// user power preferences; see README for how to restore.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"50hxcore"

	"golang.org/x/sys/windows"
)

var silent bool

// ---- GUI helpers (no console, message box + log) ----

const (
	mbIconInfo  = 0x40
	mbIconError = 0x10
)

var (
	procMsgBoxW       = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	procCreateMutex   = syscall.NewLazyDLL("kernel32.dll").NewProc("CreateMutexW")
	procShellExecuteW = syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")
)

func msgbox(title, text string, icon uint) {
	// With -y / -silent (automation) do not pop a dialog.
	if silent {
		return
	}
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(text)
	procMsgBoxW.Call(0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), uintptr(icon))
}

func setupLog(defName string) {
	p := filepath.Join(os.TempDir(), defName)
	if i := argIndex("-log"); i >= 0 && i+1 < len(os.Args) {
		p = os.Args[i+1]
	}
	if f, err := os.Create(p); err == nil {
		os.Stdout = f
		os.Stderr = f
		fmt.Fprintf(f, "==== 50HX tool %s ====\n", time.Now().Format("2006-01-02 15:04:05"))
	}
}

func lockOnce(name string) func() {
	n, _ := syscall.UTF16PtrFromString(name)
	h, _, e := procCreateMutex.Call(0, 0, uintptr(unsafe.Pointer(n)))
	if h == 0 {
		return nil
	}
	if e == syscall.ERROR_ALREADY_EXISTS {
		syscall.CloseHandle(syscall.Handle(h))
		return nil
	}
	return func() { syscall.CloseHandle(syscall.Handle(h)) }
}

// selfElevate: when not admin, ShellExecute "runas" relaunches self
// (triggers UAC); the parent then exits.
func selfElevate() {
	exe, _ := os.Executable()
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	args := append([]string{}, os.Args[1:]...)
	args = append(args, "-elevated")
	params, _ := syscall.UTF16PtrFromString(strings.Join(args, " "))
	r, _, _ := procShellExecuteW.Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)), 0, 1)
	if r <= 32 {
		msgbox("50HX Uninstaller", fmt.Sprintf("Elevation failed (error code %d).\nPlease right-click this program -> Run as administrator.", r), mbIconError)
	}
	os.Exit(0)
}

func main() {
	for _, a := range os.Args {
		if a == "-y" || a == "-silent" {
			silent = true
		}
	}
	// GUI build: mirror output to the log file.
	setupLog("50HX_uninstaller.log")
	fmt.Println("==============================================")
	fmt.Println("  CMP 50HX Windows Unlock Uninstaller v3.0.0")
	fmt.Println("  Removes: scheduled tasks / unlock boot entry / ESP EFI / Gen2 auto-start / drivers")
	fmt.Println("==============================================")
	if !isAdmin() {
		if hasArg("-elevated") {
			// We already tried elevation and still failed (silent-elevation
			// policy / restricted token) — break the loop and report.
			msgbox("50HX Uninstaller", "Elevation failed: the current account cannot obtain administrator rights.\nPlease right-click this program -> Run as administrator.", mbIconError)
			return
		}
		selfElevate()
		return
	}
	if lockOnce(`Local\40HXUninstaller_v1`) == nil {
		msgbox("50HX Uninstaller", "The uninstaller is already running, please do not click again.", mbIconInfo)
		return
	}

	// 1. Scheduled tasks (legacy boot task / Gen2 logon task / retry task / GSP fix task).
	fmt.Print("[1/8] Remove scheduled tasks ... ")
	if delTasks() {
		fmt.Println("done")
	} else {
		fmt.Println("not found (skipped)")
	}

	// 2. Gen2 Run key.
	fmt.Print("[2/8] Remove Gen2 logon auto-start ... ")
	delRunKey()
	fmt.Println("done")

	// 3. Firmware boot entry.
	fmt.Print("[3/8] Remove firmware boot entry '50HX Unlock' ... ")
	if delBootEntry() {
		fmt.Println("done")
	} else {
		fmt.Println("not found (may already be removed)")
	}

	// 4. ESP unlock EFI files.
	fmt.Print("[4/8] Remove ESP unlock EFI ... ")
	if delEspEfi() {
		fmt.Println("done")
	} else {
		fmt.Println("not found / skipped")
	}

	// 5. Driver services.
	fmt.Println("[5/8] Stop and remove driver services...")
	hxcore.UninstallDriverServices()

	// 6. Driver files.
	fmt.Println("[6/8] Remove driver files...")
	hxcore.UninstallDriverFiles()

	// 6.5 GSP registry (restore default off).
	fmt.Print("[6.5/8] Remove EnableGpuFirmware (restore GSP default off) ... ")
	if delGspKey() {
		fmt.Println("done")
	} else {
		fmt.Println("not found (skipped)")
	}

	// 6.6 ProgramData residue: gen2_status.txt (the diagnostic tool
	// surfaces it as "result"!), the drivers backup source, and the
	// policy key.
	fmt.Print("[6.6/8] Clean up %ProgramData%\\50HXUnlock + policy key ... ")
	delProgramData()
	fmt.Println("done")

	// 6.7 Defender exclusion cleanup (the whitelist added by the
	// installer; uninstall must remove it without leftovers).
	fmt.Print("[6.7/8] Clean up Defender exclusions ... ")
	if err := removeDefenderExclusions(); err != nil {
		fmt.Println("not executed (ignorable):", err)
	} else {
		fmt.Println("done")
	}

	// 7. State confirmation.
	fmt.Println("[7/8] Check for leftovers...")
	leftover := checkLeftover()

	fmt.Println()
	fmt.Println("Uninstall complete. A reboot is recommended.")
	// v2.6.0: Fast Startup / ASPM were turned off by the installer as a
	// power preference — uninstall does not roll them back.
	fmt.Println("  Note: power settings adjusted at install time (Fast Startup / PCIe link power saving) were left untouched — see README for how to restore.")
	if silent {
		return
	}
	icon := uint(mbIconInfo)
	txt := "Uninstall complete.\nA reboot is recommended.\n" +
		"\nNote: power settings adjusted at install time (Fast Startup / PCIe link power saving)\nwere left untouched — they are power preferences; see README §2.4 for how to restore.\n"
	if leftover != "" {
		icon = mbIconError
		txt += "\nLeftovers remain:\n" + leftover
	}
	txt += "\nFull log: " + filepath.Join(os.TempDir(), "50HX_uninstaller.log")
	msgbox("50HX Uninstaller", txt, icon)
}

func argIndex(name string) int {
	for i, a := range os.Args {
		if a == name {
			return i
		}
	}
	return -1
}

func hasArg(name string) bool {
	for _, a := range os.Args {
		if a == name {
			return true
		}
	}
	return false
}

func isAdmin() bool {
	t, err := windows.OpenCurrentProcessToken()
	if err == nil {
		defer t.Close()
		var buf [4]byte
		var need uint32
		if err = windows.GetTokenInformation(t, windows.TokenElevation,
			&buf[0], uint32(len(buf)), &need); err == nil && buf[0] != 0 {
			return true
		}
		// TokenElevation may falsely report 0 in restricted contexts
		// (sandbox / service); try SCM with full rights as a fallback.
	}
	// Fallback: being able to open the Service Control Manager with
	// ALL_ACCESS = real administrator.
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err == nil {
		windows.CloseServiceHandle(scm)
		return true
	}
	return false
}

// ---- v2.6.0: cleanup step implementations are lifted into
//               50hxcore/uninstall_ops.go — the following are thin
//               orchestration wrappers ----

func delTasks() bool        { return len(hxcore.UninstallTasks()) > 0 }
func delRunKey()            { hxcore.UninstallRunKey() }
func delBootEntry() bool    { return hxcore.UninstallBootEntry() }
func delEspEfi() bool       { return hxcore.UninstallEspEfi() }
func delGspKey() bool       { return hxcore.UninstallGspKey() }
func delProgramData()       { hxcore.UninstallProgramData() }
func checkLeftover() string { rem := hxcore.CheckLeftover(); return strings.Join(rem, "\n") }

func removeDefenderExclusions() error { return hxcore.RemoveDefenderExclusions() }
