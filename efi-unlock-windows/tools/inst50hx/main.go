// 50HX one-click installer v3.0.0 (CMP 50HX Windows Unlock Installer)
// Features:
//
//	(default) Install: GSP enable (EnableGpuFirmware=1) + dual ESP deploy 50HXUNLK.EFI (V70)
//	      + BootOrder set-as-first + drivers + Gen2 auto-start
//	-gen2        Run Gen2 unlock immediately (called by logon auto-start; idempotent)
//	-uninstall   Uninstall (removes boot entry / Run key / driver services / EnableGpuFirmware)
//	-status      Status check
//
// Embedded resources (v2.5): 50HXUNLK.EFI (V70 unlock) / ThrottleStop.sys / WinRing0x64.sys
// v2.6.0 critical fixes (community #2 / #5 / #6 / #7 + v2.4.5-era troubleshooting conclusions):
//  1. EFI deploy failure no longer aborts install — Legacy/MBR (no ESP) only skips the two EFI steps, Gen2 task
//     is registered as usual (previously [5/8] returned directly, the unified root cause of "drivers installed but Gen2 doesn't run at boot")
//  2. Boot-mode detection (GetFirmwareType): Legacy -> popup gives the full mbr2gpt lossless conversion guide
//  3. After scheduled-task creation, schtasks /query double-checks + retries; -task failures exit with non-zero code
//     (the errorlevel check on command-line invocation goes from dead code to effective)
//  4. Auto-disable Fast Startup (hybrid hibernate) and PCIe link power saving (ASPM) — the former avoids "shutdown then power-on
//     skipping a full UEFI boot", the latter reduces idle downshifts to Gen1 being misread as an unlock failure
//  5. Gen2 core enhancement: LNKCTL2 read-modify-write (without clearing high bits) + alternating root/GPU retrain up to 4 rounds +
//     TLS target rate decides success (idle power-saving downshift to Gen1 no longer false-reports failure)
// v2.6.0 critical hardening (auto-start channel design + concurrency safety; addressing "worry about multiple auto-start paths"):
//  1. Gen2 single-instance kernel mutex (Global\50HXGen2SingleInstance): SYSTEM task / Run key /
//     manual -gen2 — even when triggered concurrently, only one process enters the "load/unload BYOVD drivers + grab BAR0"
//     critical section, eliminating the state corruption caused by two processes contending for driver service names and link registers
//  2. Auto-start channels converged to "two mutually-exclusive serial paths": Run key tries first at logon (may fail if the GPU isn't ready,
//     silently cedes), SYSTEM task delays 30s and confirms; the other 13 path types (outside HKCU/HKLM Run)
//     all run in user mode and cannot `sc start` a kernel driver, so they are not used (see design doc)
//  3. Locate the 50HX; retry up to 3 times (2s interval), tolerating false failures from slow GPU initialization
// v2.4 key changes (community compatibility):
//  1. Embedded EFI reverted to V70 original (793d765e, user-verified unlock success) — the lesson from v2.1/v2.2 stripped-version failures
//  2. Dual ESP deploy: \EFI\50HX\50HXUNLK.EFI (BCD primary path)
//     + \EFI\Boot\bootx64.efi (UEFI-standard fallback; original backed up as .50hx.bak)
//     Fixes the "installed then no effect after reboot" on motherboards that ignore non-standard EFI paths / BCD displayorder
//  3. After writing BootOrder, read it back from firmware to verify; when not first, explicitly popup to prompt manual BIOS promotion
//  4. Critical BIOS operations all go through message boxes (community users don't read the README / log)
//
// v2.3 key: EnableGpuFirmware=1 enables GSP — 50HX's default GSP-off (CPU-RM mode)
//
//	causes nvlddmkm to reject SEC2 status after EFI unlock -> Code 43 black screen; GSP-RM mode accepts the unlock.
package main

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"50hxcore"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed embed/*
var embedded embed.FS

const (
	gpuVenDev = "VEN_10DE&DEV_1E09"
	efiDir    = "\\EFI\\50HX"
	efiFile   = "50HXUNLK.EFI"
	bootDesc  = "50HX Unlock"
	// v2.4: UEFI-standard fallback path (automatically tried when all firmware BootOrder entries are invalid / unsigned;
	// fixes motherboards that ignore BCD displayorder / do not recognize non-standard \EFI\50HX directories)
	efiStdDir = "\\EFI\\Boot"
	efiStdF   = "bootx64.efi"
	efiBakExt = ".50hx.bak" // Original-file backup for bootx64.efi.50hx.bak
	// v2.3: GSP-enable registry (EnableGpuFirmware=1) — key to no-black-screen after unlock!
	// 50HX display-adapter Class subkey (0001 = 40HX; on multi-GPU systems find by AdapterString)
	gpuClassPath  = `SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}`
	gpuClassGUID  = `{4d36e968-e325-11ce-bfc1-08002be10318}` // Used for the Driver-value reverse-lookup
	gpuEnableFw   = "EnableGpuFirmware"
	gpuAdapterStr = "HardwareInformation.AdapterString"
	gpuAdapter40  = "CMP 50HX"
	// v2.4.6: Gen2 SYSTEM scheduled task name (deleted by name during uninstall)
	gen2TaskName = "50HX PCIe Gen2 Bring-up"
	// v2.6.0: Gen2 automatic retry task after failure (one-shot; deleted on success; cleaned by name in the uninstall chain)
	gen2RetryTask = "50HXGen2Retry"
)

func main() {
	// GUI no-console build (v1.1): all output mirrored to a log (default %TEMP%\50HX_installer.log, override with -log)
	setupLog("50HX_installer.log")
	// v2.6.0: double-click (no args) or UAC re-elevation (-elevated) defaults to the GUI management window;
	// command-line flags (-gen2 / -task / -uninstall / -status / -silent / -hard) keep their semantics.
	if len(os.Args) <= 1 || (len(os.Args) == 2 && os.Args[1] == "-elevated") {
		runGUI()
		return
	}
	// install / -uninstall require administrator: when not elevated, automatically ShellExecute runas to pop UAC and relaunch
	needAdmin := true
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-gen2", "-gspensure", "-status", "-h", "-help", "--help":
			needAdmin = false
		}
		// -task requires admin (GUI double-click auto-UAC; gen2/status etc. read-only or called by SYSTEM task — no admin needed)
		if os.Args[1] == "-task" {
			needAdmin = true
		}
	}
	if needAdmin && !isAdmin() {
		if hasArg("-elevated") {
			// Already tried elevation and still failed (e.g. restricted token under silent-elevation policy) -> break the loop and report directly
			msgbox("50HX Installer", "Elevation failed: this account cannot get administrator rights.\nPlease right-click this program -> Run as administrator.", mbIconError)
			return
		}
		selfElevate()
		return
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-gen2":
			gen2Main()
			// v3.0.1: Resident guardian — started by the logon task with -guard; the driver stays loaded and Gen2 is self-checked every minute
			if hasArg("-guard") && hxcore.DriverStrategy() == hxcore.DriverStrategyResident {
				residentGuard()
			}
			return
		case "-gspensure":
			gspEnsureMain()
			return
		case "-uninstall":
			uninstall()
			return
		case "-status":
			status()
			return
		case "-task":
			// Only register the Gen2 logon auto-start task (called by -task mode;
			// the /TR quoting is built by Go to avoid embedded-quote parsing errors / crashes in the .bat)
			regTaskOnly()
			return
		case "-h", "-help", "--help":
			printHelp()
			return
		}
	}
	install()
}

// regTaskOnly: only registers the Gen2 SYSTEM task (does not install drivers / EFI / GSP).
// -task mode's last step calls this — Go handles the quoting.
// v2.6.0: exit with non-zero code on failure — the bat's errorlevel check depends on it (previously always 0, making the check dead code).
func regTaskOnly() {
	if !isAdmin() {
		fmt.Println("[!] Registering the scheduled task requires administrator rights.")
		msgbox("50HX Installer", "Registering the scheduled task requires administrator rights.\nPlease run as administrator.", mbIconError)
		os.Exit(1)
	}
	if err := setupGen2Task(); err != nil {
		fmt.Println("[!]", err)
		msgbox("50HX Installer", "Gen2 logon auto-start task registration failed:\n"+err.Error()+
			"\n\nPlease run as administrator and try again.", mbIconError)
		os.Exit(1)
	}
	// v2.6.0: Run key = try once at logon (may fail if GPU isn't ready yet, silently cedes);
	// SYSTEM task delays 30s to confirm. Both are serialized by gen2Main's single-instance mutex so they can't race for the driver.
	setRunKey()
	msgbox("50HX Installer", "Gen2 logon auto-start task registered.\nGen2 unlock will run automatically at next logon (silent, drivers are removed when done).", mbIconInfo)
}

// selfElevate: when not admin, ShellExecute "runas" to relaunch self (triggers UAC); the parent exits.
// Under the GUI subsystem there is no console; elevation failure is shown via a message box.
func selfElevate() {
	exe, _ := os.Executable()
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	// Append the -elevated marker: if the new instance is still not admin, do not re-elevate (prevents infinite loop)
	args := append([]string{}, os.Args[1:]...)
	args = append(args, "-elevated")
	params, _ := syscall.UTF16PtrFromString(strings.Join(args, " "))
	r, _, _ := procShellExecuteW.Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)), 0, 1)
	if r <= 32 {
		msgbox("50HX Installer", fmt.Sprintf("Elevation failed (error code %d).\nPlease right-click this program -> Run as administrator.", r), mbIconError)
	}
	os.Exit(0)
}

var (
	procShellExecuteW = syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")
)

const (
	mbIconInfo  = 0x40
	mbIconError = 0x10
	mbIconWarn  = 0x30 // MB_ICONWARNING — v2.6.0: "can continue but pay attention" scenarios such as EFI skipped / partial success
	mbYesNo     = 0x04 // MB_YESNO -> returns IDYES=6 / IDNO=7
)

var (
	procMsgBoxW     = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	procCreateMutex = syscall.NewLazyDLL("kernel32.dll").NewProc("CreateMutexW")
)

func msgbox(title, text string, icon uint) {
	// With -y / -silent (automation / auto-start), do not pop a dialog
	if hasArg("-y") || hasArg("-silent") {
		return
	}
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(text)
	procMsgBoxW.Call(0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), uintptr(icon))
}

// msgboxYesNo: yes/no prompt. Auto mode: -y -> true (fully automatic continue), -silent -> false (do not disturb).
func msgboxYesNo(title, text string) bool {
	if hasArg("-y") {
		return true
	}
	if hasArg("-silent") {
		return false
	}
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(text)
	r, _, _ := procMsgBoxW.Call(0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), uintptr(mbYesNo|mbIconInfo))
	return r == 6 // IDYES
}

// setupLog: mirror output to a log file (default %TEMP%/<name>; command-line -log <file> takes precedence)
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

// AttachLogSink: for the v2.6.0 GUI — use an os.Pipe to split subsequent fmt.* output to BOTH the log file and the UI.
// fmt.* reads the os.Stdout variable on each call; but os.Stdout itself is a concrete *os.File,
// which can't be assigned to io.Writer, so we replace it with the pipe's write end; a reader goroutine writes to both the original file and the GUI log panel.
func AttachLogSink(w io.Writer) {
	r, pw, err := os.Pipe()
	if err != nil {
		return
	}
	orig := os.Stdout // Log file set up by setupLog (or the invalid console handle under the GUI)
	os.Stdout = pw
	os.Stderr = pw
	go func() {
		defer r.Close()
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				orig.Write(buf[:n]) // Write to the log file (failures under GUI mode are ignorable)
				w.Write(buf[:n])    // Feed the GUI log panel
			}
			if rerr != nil {
				return
			}
		}
	}()
}

// lockOnce: single-instance mutex; returns nil when another instance is already running
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

func hasArg(name string) bool {
	for _, a := range os.Args {
		if a == name {
			return true
		}
	}
	return false
}

func argIndex(name string) int {
	for i, a := range os.Args {
		if a == name {
			return i
		}
	}
	return -1
}

func printHelp() {
	fmt.Println("CMP 50HX Windows one-click unlock installer")
	fmt.Println("  Usage: 50HXInstaller.exe            # install (requires admin)")
	fmt.Println("         50HXInstaller.exe -gen2      # run Gen2 unlock now")
	fmt.Println("         50HXInstaller.exe -uninstall # uninstall")
	fmt.Println("         50HXInstaller.exe -status    # print status")
}

// ===================== Low level =====================

func isAdmin() bool {
	var t windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t)
	if err == nil {
		defer t.Close()
		var e uint32
		var n uint32
		if err = windows.GetTokenInformation(t, windows.TokenElevation,
			(*byte)(unsafe.Pointer(&e)), uint32(unsafe.Sizeof(e)), &n); err == nil && e != 0 {
			return true
		}
		// TokenElevation may falsely report 0 in restricted contexts (sandbox / service); try SCM full-rights as a fallback
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err == nil {
		windows.CloseServiceHandle(scm)
		return true
	}
	return false
}

// enableGsp: sets EnableGpuFirmware=1 (requires admin)
func enableGsp() error {
	key := hxcore.FindGpuClassKey()
	if key == "" {
		return errors.New("Could not find the 50HX device registry key (Class subkey)")
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(gpuEnableFw, 1)
}

// disableGsp: deletes EnableGpuFirmware (used by uninstall; restores the default-off state)
func disableGsp() {
	key := hxcore.FindGpuClassKey()
	if key == "" {
		return
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	k.DeleteValue(gpuEnableFw)
}

// ensureGspSilent: ensures GSP is enabled (EnableGpuFirmware=1).
// Called by -gen2 (logon auto-start): if GSP was reset (≠1), re-enable it.
// Writing HKLM requires admin: if currently admin, write directly; otherwise register a one-shot SYSTEM scheduled task
// (SYSTEM permissionss can write HKLM without UAC, no window).
// Returns true = GSP is already enabled or its reset has been scheduled.
func ensureGspSilent() bool {
	if hxcore.GspEnabled() {
		return true // already enabled
	}
	fmt.Println("[GSP] EnableGpuFirmware was reset, re-enabling...")
	if isAdmin() {
		if err := enableGsp(); err != nil {
			fmt.Println("[GSP] Re-set failed:", err)
			return false
		}
		fmt.Println("[GSP] EnableGpuFirmware=1 re-set (takes effect after reboot via GSP-RM)")
		return true
	}
	// Not admin: use a one-shot SYSTEM scheduled task to re-set (no UAC prompt)
	exe, _ := os.Executable()
	abs, _ := filepath.Abs(exe)
	tn := "50HXGspEnsure"
	if out, err := hxcore.RunOut("schtasks.exe", "/create", "/tn", tn,
		"/tr", fmt.Sprintf("\"%s\" -gspensure -silent", abs),
		"/sc", "once", "/st", "00:00", "/ru", "SYSTEM", "/f"); err != nil {
		fmt.Printf("[GSP] Scheduled task creation failed: %s\n", strings.TrimSpace(out))
		return false
	}
	hxcore.RunOut("schtasks.exe", "/run", "/tn", tn)
	hxcore.RunOut("schtasks.exe", "/delete", "/tn", tn, "/f")
	fmt.Println("[GSP] EnableGpuFirmware=1 re-set via SYSTEM task")
	return true
}

// gspEnsureMain: -gspensure mode (called by the SYSTEM scheduled task; only re-sets GSP then exits)
func gspEnsureMain() {
	if isAdmin() {
		if err := enableGsp(); err != nil {
			fmt.Println("[GSP] gspensure re-set failed:", err)
			return
		}
		fmt.Println("[GSP] gspensure: EnableGpuFirmware=1 set")
	}
}

func copyEmbedTo(target string, src string) error {
	data, err := embedded.ReadFile("embed/" + src)
	if err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o644)
}

// deployEspEfi: dual-path deploy 50HXUNLK.EFI to the already-mounted ESP <esp>.
//
//	A. \EFI\50HX\50HXUNLK.EFI   — BCD boot-entry reference path
//	B. \EFI\Boot\bootx64.efi    — UEFI-standard fallback path (firmware's unconditional last resort;
//	   fixes the widespread community case of "installed then rebooted straight into Windows without running the unlock" — motherboards ignoring non-standard directories)
//
// Backup rule: if the target bootx64.efi exists and is not a copy already deployed by this tool, back it up first as
//
//	bootx64.efi.50hx.bak (restored on uninstall). If already deployed (.bak exists), overwrite directly.
//
// Returns whether the fallback path freshly backed up the original file.
func deployEspEfi(esp string) (backedUp bool, err error) {
	// Read embed once; both paths share it
	data, rerr := embedded.ReadFile("embed/50HXUNLK.EFI")
	if rerr != nil {
		return false, rerr
	}
	// Verify the embed data itself before writing (PE header + reasonable length, defend against embed corruption)
	if len(data) < 0x2000 { // an EFI file smaller than 8 KB is definitely corrupt
		return false, fmt.Errorf("embedded 50HXUNLK.EFI data is invalid (%d bytes)", len(data))
	}
	if !bytes.HasPrefix(data, []byte("MZ")) {
		return false, errors.New("embedded 50HXUNLK.EFI is not a valid PE image (missing MZ header)")
	}

	// A. Primary path
	dirA := esp + ":" + efiDir // Y:\EFI\40HX
	if merr := os.MkdirAll(dirA, 0o644); merr != nil {
		return false, merr
	}
	pA := filepath.Join(dirA, efiFile)
	if werr := writeVerified(pA, data); werr != nil {
		// Write failure or verify mismatch -> delete the possibly half-written file so BCD doesn't reference a broken boot
		os.Remove(pA)
		return false, werr
	}
	fmt.Printf("    [A] %s  (%d bytes, verified OK)\n", "\\EFI\\50HX\\"+efiFile, len(data))

	// B. Standard fallback path
	dirB := esp + ":" + efiStdDir // Y:\EFI\Boot
	if merr := os.MkdirAll(dirB, 0o644); merr != nil {
		return false, merr
	}
	pB := filepath.Join(dirB, efiStdF) // bootx64.efi
	pBak := pB + efiBakExt             // bootx64.efi.50hx.bak
	if _, berr := os.Stat(pBak); berr != nil {
		// No backup record -> if the target exists and is not a copy we deployed, back it up first
		if old, oerr := os.ReadFile(pB); oerr == nil && !bytes.Equal(old, data) {
			if cerr := os.Rename(pB, pBak); cerr != nil {
				return false, fmt.Errorf("backing up original %s failed: %v", pB, cerr)
			}
			fmt.Printf("    [B] Original %s backed up as %s\n", efiStdF, efiStdF+efiBakExt)
			backedUp = true
		} else if oerr != nil {
			// Target does not exist: no backup (the slot was empty)
		}
	}
	if werr := writeVerified(pB, data); werr != nil {
		os.Remove(pB)
		return backedUp, werr
	}
	fmt.Printf("    [B] %s  (%d bytes, verified OK)\n", "\\EFI\\Boot\\"+efiStdF, len(data))
	return backedUp, nil
}

// writeVerified: read-back-compare after writing — prevents boot damage from write interruption / half-written files.
// On mismatch, delete and return an error (the caller aborts, keeping broken files off the boot path).
func writeVerified(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	rb, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("post-write verification read of %s failed: %v", path, err)
	}
	if !bytes.Equal(rb, data) {
		return fmt.Errorf("post-write verification mismatch for %s (%d != %d bytes)", path, len(rb), len(data))
	}
	return nil
}

// alreadyInstalled: detects whether the install was already performed (avoids meaningless / redundant overwrites).
// Criteria: ① the "50HX Unlock" firmware boot entry exists; ② \EFI\50HX\50HXUNLK.EFI is already on the ESP.
// Either hit counts as installed — used for re-entry hints (does not block the user, only prompts confirmation).
func alreadyInstalled() bool {
	// ① bcdedit firmware enum (no ESP mount, fast)
	if out, _ := hxcore.RunOut("bcdedit.exe", "/enum", "firmware"); strings.Contains(out, bootDesc) {
		return true
	}
	// ② ESP file
	esp := hxcore.MountESP()
	if esp == "" {
		return false // when the ESP cannot be mounted, conservatively treat as not installed ([5/8] will report the boot error later)
	}
	defer hxcore.UnmountESP(esp)
	if _, err := os.Stat(esp + ":" + efiDir + "\\" + efiFile); err == nil {
		return true
	}
	return false
}

// verifyBootEntry: reads back the {fwbootmgr} displayorder, confirms whether 50HX Unlock is first.
// Returns (exists, isFirst, displayOrder description).
// Uses bcdedit /enum firmware to read the firmware NVRAM — if the firmware ignores what bcdedit wrote,
// this reflects reality (not in the list / not first), letting the installer emit BIOS manual guidance.
// Note: bcdedit output is GBK; on Chinese systems "identifier / description" render as mojibake; but the field values
// (guid / displayorder / 50HX Unlock / path) are all ASCII, so block-based parsing is reliable.
func verifyBootEntry() (bool, bool, string) {
	out, err := hxcore.RunOut("bcdedit.exe", "/enum", "firmware")
	if err != nil {
		return false, false, "(bcdedit read failed: " + err.Error() + ")"
	}
	lines := strings.Split(out, "\r\n")
	if len(lines) < 2 {
		lines = strings.Split(out, "\n")
	}

	// 1. Collect the GUID sequence under displayorder (firmware's actual boot order)
	var order []string
	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if strings.HasPrefix(t, "displayorder") {
			// The first GUID can be on the same line: "displayorder {guid}"
			if m := guidRe().FindString(t); m != "" {
				order = append(order, strings.Trim(m, "{}"))
			}
			// Subsequent indented {guid}
			for j := i + 1; j < len(lines); j++ {
				s := strings.TrimSpace(lines[j])
				if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
					order = append(order, strings.Trim(s, "{}"))
				} else if s != "" {
					break
				}
			}
			break // displayorder only appears in the {fwbootmgr} section, the first one is enough
		}
	}

	// 2. Find the GUID of the block whose description is "50HX Unlock"
	target := ""
	for i := 0; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "description") &&
			strings.Contains(lines[i], bootDesc) {
			// Walk upward to the nearest {guid} line = this block's identifier
			for j := i - 1; j >= 0 && j > i-6; j-- {
				if m := guidRe().FindString(lines[j]); m != "" {
					target = strings.Trim(m, "{}")
					break
				}
			}
			break
		}
	}
	if target == "" {
		joined := strings.Join(order, " > ")
		if joined == "" {
			joined = "(firmware has no displayorder entries)"
		}
		return false, false, joined
	}
	if len(order) == 0 {
		return true, false, "(displayorder is empty)"
	}
	isFirst := order[0] == target
	return true, isFirst, strings.Join(order, " > ")
}

var _guidRe = regexp.MustCompile(`\{([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}`)

func guidRe() *regexp.Regexp { return _guidRe }

// ===================== Install =====================

// applyPowerSettings: two power optimizations — Fast Startup + PCIe ASPM (extracted from the v2.6.0 [3.6/8] step,
// reused by the v2.6.0 GUI policy page). Idempotent: leaves alone if already off; returns per-item note lines.
func applyPowerSettings() []string {
	notes := []string{}
	if hxcore.FastStartupOn() {
		if err := hxcore.SetFastStartupOff(); err != nil {
			notes = append(notes, fmt.Sprintf("Disabling Fast Startup failed: %v (does not block install, recommend turning it off manually in Power Options)", err))
		} else {
			notes = append(notes, "Fast Startup disabled (was on): shutdown will now go through a full UEFI boot; Power Options can revert this")
		}
	} else {
		notes = append(notes, "Fast Startup: was already off (OK)")
	}
	if ac, dc, ok := hxcore.ASPMSavings(); !ok {
		notes = append(notes, "PCIe ASPM: this machine does not expose this setting, skipping")
	} else if ac == 0 && dc == 0 {
		notes = append(notes, "PCIe ASPM: was already off (OK)")
	} else {
		if err := hxcore.SetASPMOff(); err != nil {
			notes = append(notes, fmt.Sprintf("Disabling ASPM failed: %v", err))
		} else {
			notes = append(notes, fmt.Sprintf("PCIe ASPM disabled (was AC=%d/DC=%d): reduces idle downshift to Gen1; revert with the powercfg command in the README", ac, dc))
		}
	}
	return notes
}

// installEFI: dual-path ESP deploy of 50HXUNLK.EFI + firmware boot entry (extracted from v2.6.0 [5/8]+[6/8] steps,
// reused by the v2.6.0 GUI components page). Returns whether the EFI deploy succeeded;
// [7/8] Gen2 task registration does NOT depend on this (an EFI failure only skips the two EFI steps — the unified fix for community #2/#5/#6/#7).
func installEFI() bool {
	//    Primary path  \EFI\50HX\50HXUNLK.EFI  — BCD boot entry reference
	//    fallback \EFI\Boot\bootx64.efi   — UEFI-standard fallback, fixes motherboards that
	//    ignore BCD displayorder / do not recognize non-standard directories (the main community cause of "installed then no effect after reboot").
	//    Original bootx64.efi is backed up as bootx64.efi.50hx.bak; restored on uninstall.
	efiOK := false
	fmt.Println("    · Deploying unlock EFI to the system EFI partition (dual path)...")
	esp := hxcore.MountESP()
	if esp == "" {
		if hxcore.FirmwareIsLegacy() {
			fmt.Println("[!] This system uses Legacy BIOS+MBR boot — there is no EFI partition, the unlock EFI cannot be deployed.")
			fmt.Println("    Compute unlock requires UEFI+GPT: please use Microsoft mbr2gpt for a lossless conversion first (full steps in the popup),")
			fmt.Println("    then change boot to UEFI and re-run this installer.")
			fmt.Println("    [i] Gen2 logon auto-start is unaffected; continuing to register it (see [7/8]).")
			msgbox("50HX Installer (convert disk to GPT first)",
				"This system uses Legacy BIOS+MBR boot, there is no EFI partition,\n"+
					"the compute-unlock EFI cannot be deployed — this is why \"the EFI install doesn\\'t work\".\n\n"+
					"Please first convert to UEFI+GPT (Microsoft's official lossless conversion, no data touched):\n"+
					"  1. Back up important data; make sure BitLocker is NOT enabled (suspend it first if it is)\n"+
					"  2. In an administrator command prompt run:  mbr2gpt /validate /allowfullos\n"+
					"  3. After seeing Validation completed successfully, run:\n"+
					"        mbr2gpt /convert /allowfullos\n"+
					"  4. Reboot into the BIOS and change the boot mode from Legacy to UEFI (disable CSM)\n"+
					"  5. After entering Windows, re-run this installer\n\n"+
					"Note: the conversion is irreversible; requires Win10 1703+ / Win11 and a UEFI-capable motherboard.\n"+
					"This install will continue and finish the Gen2 portion (compute unlock will take effect after the conversion and re-running the installer).",
				mbIconWarn)
		} else {
			fmt.Println("[!] Unable to mount the EFI partition (mountvol /S failed)")
			fmt.Println("    The system is UEFI; common causes: BitLocker / third-party encryption not suspended, abnormal ESP partition.")
			fmt.Println("    Manual workaround: mountvol S: /S, copy 50HXUNLK.EFI to S:\\EFI\\50HX\\, mountvol S: /D")
			msgbox("50HX Installer (EFI partition mount failed)",
				"Unable to mount the EFI partition (mountvol /S failed); the unlock EFI was not deployed this run.\n"+
					"System boot is unaffected.\n\n"+
					"Common causes: BitLocker / third-party encryption not suspended, abnormal ESP partition.\n"+
					"You can deploy manually (see the log and \"EFI emergency repair guide.md\").\n\n"+
					"This install will continue and finish the Gen2 portion; compute unlock takes effect once the EFI is deployed.",
				mbIconWarn)
		}
		return false
	}
	fmt.Printf("    ESP mounted at %s: \\\\\\n", esp)
	fb, err := deployEspEfi(esp)
	hxcore.UnmountESP(esp)
	if err != nil {
		fmt.Println("[!] Failed to copy EFI:", err)
		msgbox("50HX Installer (EFI write failed)",
			"Copying the unlock EFI to the ESP failed (post-write verify was done, no broken file left behind):\n"+err.Error()+
				"\n\nSystem boot is unaffected; a reboot should still enter Windows normally.\n\n"+
				"For manual deployment, see \"EFI emergency repair guide.md\" in this directory:\n"+
				"the \"manual deployment\" section.\n\n"+
				"This install will continue and finish the Gen2 portion.", mbIconWarn)
		return false
	}
	if fb {
		fmt.Println("    [!] Original bootx64.efi detected; backed up as bootx64.efi.50hx.bak")
	}
	efiOK = true

	// BootOrder (v2.4: write-back verify + BIOS-guidance popup); only runs when EFI deploy succeeded
	fmt.Println("    · Setting the firmware boot entry (50HX Unlock set as first)...")
	bootOK := false
	if err := setupBootEntry(); err != nil {
		fmt.Println("[!] Auto-set boot entry failed:", err)
	} else {
		if ex, first, ord := verifyBootEntry(); ex {
			bootOK = first
			if first {
				fmt.Println("    Boot entry set as first and verified (first in firmware displayorder)")
			} else {
				fmt.Println("    [!] Boot entry was created, but it is NOT first in displayorder:")
				fmt.Println("        Current firmware order: " + ord)
				fmt.Println("        Please enter the BIOS and manually set '50HX Unlock' as the first boot entry (see popup)")
			}
		} else {
			fmt.Println("    [!] Could not find the '50HX Unlock' entry in the firmware boot list")
			fmt.Println("        (some motherboards ignore BCD writes; please add / set as first in the BIOS manually)")
		}
	}
	if !bootOK {
		// BIOS guidance popup (the key step for community users who don't read the log / README)
		msgbox("50HX Installer (IMPORTANT: please follow the steps)",
			"The auto-created boot entry was not accepted by the firmware.\n"+
				"Please reboot and press Del/F2 to enter the BIOS; complete the following (otherwise the unlock will not happen):\n\n"+
				"1. Disable Secure Boot (if it is on, unsigned EFI is rejected)\n"+
				"2. Disable Fast Boot / quick boot if present\n"+
				"3. In [Boot Priority / Boot Order], set '50HX Unlock' as the first entry\n"+
				"   or manually pick the boot device \\EFI\\50HX\\50HXUNLK.EFI\n"+
				"4. If the list shows only Windows Boot Manager:\n"+
				"   - Some motherboards only show this boot entry after disabling CSM (pure UEFI)\n"+
				"   - Or boot directly from the UEFI disk (uses the bootx64 fallback)\n\n"+
				"The installer deploys the unlock EFI to BOTH:\n"+
				"  \\EFI\\50HX\\50HXUNLK.EFI  (BCD path)\n"+
				"  \\EFI\\Boot\\bootx64.efi    (standard fallback path)\n\n"+
				"Detailed log: "+filepath.Join(os.TempDir(), "50HX_installer.log"),
			mbIconError)
	}
	return efiOK
}

func install() {
	fmt.Println("==============================================")
	fmt.Println("  CMP 50HX Windows Unlock Installer v3.0.0")
	fmt.Println("  Tensor unlock(EFI V70 + GSP enable) + PCIe Gen2 + auto-start")
	fmt.Println("==============================================")

	if !isAdmin() {
		fmt.Println("[!] Administrator requiredpermissions。")
		msgbox("50HX Installer", "Administrator permissions are required.\nPlease right-click this program -> Run as administrator.", mbIconError)
		return
	}
	if lockOnce(`Local\40HXInstaller_v1`) == nil {
		msgbox("50HX Installer", "Installer is already running. Please do not click again.", mbIconInfo)
		return
	}

	// 0. Re-entry detection: previously installed (firmware boot entry / GSP key present) -> ask for confirmation before overwrite,
	//    to prevent users from thinking they need to reinstall repeatedly, or overwriting an existing deploy unawares.
	if alreadyInstalled() {
		fmt.Println("[!] Detected a previous 50HX unlock installation (boot entry / GSP key present).")
		if !msgboxYesNo("50HX Installer",
			"A previous 50HX unlock installation was detected.\n\n"+
				"Reinstalling will overwrite the existing deployment (drivers and boot entry will be refreshed; system boot will not be damaged).\n"+
				"If you want to repair an abnormal state or upgrade, select \"Yes\" to continue;\n"+
				"if you opened this by mistake, select \"No\" to keep it as-is.\n\n"+
				"Continue with reinstall?") {
			fmt.Println("cancelled - keeping existing install unchanged.")
			return
		}
		fmt.Println("    user confirmed, continuing overwrite install.")
	}

	// 1. GPU detection
	fmt.Print("[1/8] detection GPU ... ")
	if !hxcore.FindGPU() {
		fmt.Println("not found " + gpuVenDev)
		fmt.Println("[!] CMP 50HX not detected. Aborted.")
		msgbox("50HX Installer", "CMP 50HX GPU (VEN_10DE&DEV_1E09) not detected.\nInstallation aborted.", mbIconError)
		return
	}
	fmt.Println("CMP 50HX found")

	// 2. Secure Boot
	fmt.Print("[2/8] Secure Boot check ... ")
	if hxcore.SecureBootOn() {
		fmt.Println("on!")
		fmt.Println("[!] When Secure Boot is on, the unsigned EFI (40HXUNLK) will be rejected by firmware.")
		msgbox("50HX Installer (Secure Boot must be disabled)",
			"Secure Boot is enabled - the unsigned unlock EFI will be rejected by firmware.\n\n"+
				"Please reboot, enter the BIOS to disable it, then run this installer:\n"+
				"  1. Reboot and press Del / F2 (some boards use F1/F10/F12) to enter the BIOS\n"+
				"  2. Find the Security / Boot / Start tab\n"+
				"  3. Set Secure Boot to Disabled\n"+
				"     (if greyed out, first enable CSM / compatibility mode or restore default safe settings)\n"+
				"  4. Save and exit (F10), then re-run this program\n\n"+
				"This is required for the unlock: the 50HX unlock EFI has no Microsoft signature.",
			mbIconError)
		return
	}
	fmt.Println("disabled / not available (OK)")

	// 3. Test signing (v2.5 no longer needed - BYOVD pre-signed drivers load in normal mode)
	fmt.Print("[3/8] Test signing ... ")
	if hxcore.TestSigningOn() {
		fmt.Println("on - v2.5 does not need it; after install run 'bcdedit /set testsigning off' to disable")
	} else {
		fmt.Println("disabled (OK) - v2.5 requires no test signing")
	}

	// 3.5 GSP enable (v2.3: key to avoiding a black screen after unlock!)
	// 50HX default GSP off (CPU-RM mode) -> EFI after unlock nvlddmkm rejects -> Code 43 black screen
	// EnableGpuFirmware=1 -> GSP-RM manages SEC2/booter -> accepts unlock status
	fmt.Print("[3.5/8] Enable GSP (EnableGpuFirmware) ... ")
	if hxcore.GspEnabled() {
		if sub, _, fw := hxcore.GspDiag(); sub != "" {
			fmt.Printf("enabled (OK) - Class\\%s EnableGpuFirmware=%d\n", sub, fw)
		} else {
			fmt.Println("enabled (OK)")
		}
	} else {
		if err := enableGsp(); err != nil {
			// v2.4.1: include AdapterString diagnostics - disguised drivers (e.g. recognised as 2070) hit this branch
			_, adapterDiag, _ := hxcore.GspDiag()
			fmt.Println("set failed:", err)
			if adapterDiag != "" && !strings.Contains(adapterDiag, "no CMP 50HX") {
				fmt.Println("    [!] Actual AdapterString:", adapterDiag)
			} else if adapterDiag != "" {
				fmt.Println("    [!]", adapterDiag)
			}
			fmt.Println("    [!] If this is a disguised driver (reported as 2070, etc.): swap it for a non-disguised driver or set GSP manually")
			msgbox("50HX Installer", "Setting EnableGpuFirmware=1 failed (administrator required).\nAfter unlock you may see a black screen or driver drop.\nError: "+err.Error()+"\nIf this is a disguised driver (reported as 2070, etc.), please swap it for a non-disguised driver or run -status to check AdapterString.", mbIconError)
			return
		}
		fmt.Println("Set EnableGpuFirmware=1 (takes effect after reboot)")
		fmt.Println("    [!] GSP required: otherwise the driver won't accept the post-unlock state -> Code 43 black screen")
	}

	// 3.6 system power settings (v2.6.0: community v2.4.5 troubleshooting conclusions)
	//     Fast Startup: "shutdown then power on" goes through hibernate resume, skipping a full UEFI boot - the EFI may not run
	//     PCIe ASPM: when enabled, idle downshifts to Gen1; after logon this can be misread as "Gen2 failed"
	//     Both are idempotent; only modified when currently enabled; both can be restored from the power options; other power policies are not touched
	fmt.Print("[3.6/8] Power settings (Fast Startup + PCIe link power saving) ... ")
	pwrNotes := applyPowerSettings()
	fmt.Println("done")
	for _, n := range pwrNotes {
		fmt.Println("    - " + n)
	}

	// 4. Driver install
	fmt.Println("[4/8] Preparing Gen2 BYOVD drivers (ThrottleStop + WinRing0)...")
	installDrivers()

	// 4.5 Defender precise exclusions (prevents antivirus from deleting driver files and breaking Gen2 auto-start)
	//     Only adds our own driver / backup / release directories; no system protections are disabled.
	fmt.Print("[4.5/8] Defender exclusions (prevent deletion) ... ")
	if err := hxcore.AddDefenderExclusions(); err != nil {
		fmt.Println("not run (ignorable):", err)
	} else {
		fmt.Println("Whitelisted ThrottleStop/WinRing0 driver files and backup directory")
	}

	// 5+6. EFI deploy and boot entry (v2.6.0: extracted to installEFI, reused per-component by the GUI)
	fmt.Println("[5/8]+[6/8] Deploy unlock EFI and firmware boot entry (dual-path write + displayorder promotion)...")
	efiOK := installEFI()

	// 7. Gen2 auto-start (do NOT retrain during install!)
	// Important: never run the Gen2 PCIe retrain during install. At this point nvlddmkm still owns the GPU;
	// forcing a retrain puts the GPU / link into an abnormal state, breaking the EFI takeover on next boot, or
	// failing nvlddmkm initialization (observed: device reports code 19 / Windows boots abnormally into Safe Mode).
	// Correct timing = after reboot, at logon (matches the manual recipe; verified stable).
	// v2.6.0: two-path mutex-serial design - Run key tries at logon + SYSTEM task delays 30s to confirm;
	// the single-instance mutex (gen2AcquireSingleInstance) keeps both paths from entering the driver-load critical section at once.
	// The Run key, running with normal user permissions, cannot 'sc start' a driver -> automatically deferred to the SYSTEM task (silent).
	fmt.Println("[7/8] Register Gen2 logon auto-start (SYSTEM task + Run key, mutex-serial)...")
	setRunKey()
	if err := setupGen2Task(); err != nil {
		// v2.6.0: the task is the lifeline of the Gen2 chain; a registration failure must be visible to the user with a one-click repair
		fmt.Println("[!]", err)
		msgbox("50HX Installer (Gen2 auto-start registration failed)",
			"Gen2 logon auto-start task registration failed - after logon Gen2 will not auto-unlock.\n\n"+
				"Please right-click and run as administrator once:\n"+
				"  50HXInstaller.exe -task\n\n"+
				"The rest of the install steps are done.", mbIconWarn)
	}

	fmt.Println()
	fmt.Println("Installation done!")
	if efiOK {
		fmt.Println("  Next reboot: firmware will automatically run 50HX Unlock (Tensor unlock) -> automatically enter Windows")
	} else {
		fmt.Println("  [!] EFI compute unlock was not deployed this session (see [5/8] instructions) - compute will not unlock,")
		fmt.Println("      follow the [5/8] popup guide (mbr2gpt / manual deploy) and re-run this installer afterwards.")
	}
	fmt.Println("  GSP enabled: the driver takes over the GPU in GSP-RM mode, no more black screen / driver drop after unlock")
	fmt.Println("  After logon: Gen2 auto-unlock (registered auto-start, no window, silent)")
	fmt.Println("  [!] PCIe is not retrained during install; it runs after reboot at logon (to avoid GPU driver conflicts)")
	fmt.Println("  After reboot verification: double-click 50HXCheck.exe to view the unlock status (SS0=0x88888888 means success)")
	fmt.Println("  If test signing was just enabled: please reboot once first so the driver can load")
	// v2.4: completion popup includes key BIOS / reboot guidance (community users can operate without depending on the README)
	// v2.6.0: EFI success vs failure gets different guidance; tells user how power settings were adjusted and how to restore them
	efiNote := ""
	if efiOK {
		efiNote = "Things to note at reboot:\n" +
			"  - A black screen / '50HX' text log displayed for about 10-30 seconds is normal (unlock in progress)\n" +
			"  - After the unlock completes, Windows will boot automatically\n\n" +
			"If after reboot Windows boots directly without the unlock running, please enter the BIOS (Del/F2):\n" +
			"  1. Disable Secure Boot (required for the unsigned EFI)\n" +
			"  2. Disable Fast Boot\n" +
			"  3. Set '50HX Unlock' as the first boot entry\n" +
			"     (if the list only shows Windows Boot Manager, disable CSM first then re-check)\n"
	} else {
		efiNote = "[!] This session the EFI compute unlock was not deployed (see popup / log above for the reason):\n" +
			"  - Compute will not unlock; follow the guidance and re-run the installer afterwards\n" +
			"  - Gen2 auto-start is registered and is unaffected\n"
	}
	msgbox("50HX Installer (Installation done)",
		"OK Installation done! "+map[bool]string{true: "After reboot the unlock will run automatically.", false: "Gen2 is partially ready."}[efiOK]+"\n\n"+
			efiNote +
			"\nAfter reboot and entering the system:\n"+
			"  - Double-click 50HXCheck.exe in the same directory to verify - it displays\n"+
			"    'unlock success: Tensor full (SS0=0x88888888)' when done\n"+
			"  - If a hint says it is not unlocked, the tool will suggest the next step (e.g. enable Above 4G)\n\n"+
			"- If test signing was just enabled: reboot once first so the driver can load\n"+
			"- GSP enabled (EnableGpuFirmware=1): the key to no black screen after unlock\n"+
			"- Fast Startup and PCIe link power saving (ASPM) are automatically disabled:\n"+
			"  the former ensures shutdown-then-power-on also goes through a full UEFI boot; the latter reduces idle downshifts to Gen1;\n"+
			"  See README section 2.4 for restore instructions\n"+
			"- After logon Gen2 auto-unlock (silent)\n\n"+
			"Detailed log: "+filepath.Join(os.TempDir(), "50HX_installer.log"),
		mbIconInfo)
}

func installDrivers() {
	sysDir := os.Getenv("SystemRoot") + "\\System32\\drivers"
	svcRunning := func(name string) bool {
		out, _ := hxcore.RunOut("sc.exe", "query", name)
		return strings.Contains(out, "RUNNING")
	}
	// v2.5: no longer resident 50hx_bridge (requires test signing). Gen2 switched to BYOVD:
	//   ThrottleStop (arbitrary physical memory writes, EV pre-signed) + WinRing0 (PCI config) -
	//   both load in normal mode (testsigning off). The install stage only places the driver files and
	//   registers a demand service; the actual load and self-clean are done by -gen2 at logon (SYSTEM task)
	//   -> remove-when-done, leaving no third-party driver resident in the system while gaming.
	tsApp := throttleStopAppRunning()
	for _, d := range []struct{ name, file string }{
		{"ThrottleStop", "ThrottleStop.sys"},
		{"WinRing0_1_2_0", "WinRing0x64.sys"},
	} {
		dst := filepath.Join(sysDir, d.file)
		// ThrottleStop software installed locally -> reuse its same-named driver; never overwrite / delete (to avoid conflicts and write-protection)
		if tsApp {
			fmt.Printf("  Detected ThrottleStop software, reusing its %s driver (no overwrite / no delete)\n", d.name)
			continue
		}
		if svcRunning(d.name) {
			fmt.Printf("  %s is running, skipping overwrite (keep current state)\n", d.name)
			continue
		}
		hxcore.RunOut("sc.exe", "stop", d.name)
		// Keep a copy in %ProgramData%\50HXUnlock\drivers as the persistent backup source
		// (used by 40HXCheck live testing and by Gen2 temporary deploys; the System32 copies are deleted remove-when-done)
		pdDir := filepath.Join(os.Getenv("ProgramData"), "50HXUnlock", "drivers")
		os.MkdirAll(pdDir, 0o755)
		copyEmbedTo(filepath.Join(pdDir, d.file), d.file)
		if err := copyEmbedTo(dst, d.file); err != nil {
			if _, statErr := os.Stat(dst); statErr != nil {
				fmt.Printf("  [!] Copy %s failed: %v\n", d.file, err)
				continue
			}
		} else {
			fmt.Printf("  Copied %s\n", d.file)
		}
		ensureService(d.name, d.file)
	}
	fmt.Println("  Gen2 driver files ready (demand); loaded at logon by the SYSTEM task and self-cleaned")
}

// ensureService: only registers (or updates) the driver service, does not load it here.
// Loading 50hx_bridge during the install stage (which maps GPU BAR0) would contend with the running nvlddmkm
// for the hardware; observed to cause the 50HX device to report code 19 / subsequent abnormal startup.
// Loading is deferred to -gen2 at logon after reboot.
// v2.4.6 key repair (root cause of community #1/#2):
//
//	The driver service is registered as start=demand (manual); it must be started by -gen2 after logon.
//	But -gen2 runs from the Run key with normal user permissions -> 'sc start' requires Administrator ->
	//	"[SC] StartService: OpenService failed 5: Access is denied" -> the driver never starts
//	-> Gen2 always fails (user-visible symptom: compute unlock OK but Gen2 fails).
//	Correct answer = keep demand (do NOT change to auto! see below), and elevate -gen2's run permissions to
//	SYSTEM: register a SYSTEM scheduled task (trigger at logon + delay 30s) that runs -gen2 -silent,
//	which avoids a UAC popup and preserves the safe "load driver only after logon" timing.
//
// Why not change start to auto: a type=kernel auto driver is loaded by SCM early in boot,
// which would contend with the subsequently initialising nvlddmkm for GPU BAR0 - historically observed
// to cause the 50HX to report code 19 / Windows to start abnormally into Safe Mode.
// demand + load-after-logon is the verified timing.
func ensureService(name string, sysFile string) {
	bin := fmt.Sprintf("\\SystemRoot\\System32\\drivers\\%s", sysFile)
	// create (fails if it exists - ignore); start type demand - started by the SYSTEM task after logon
	hxcore.RunOut("sc.exe", "create", name, "type=", "kernel", "start=", "demand", "binPath=", bin)
	out, err := hxcore.RunOut("sc.exe", "query", name)
	if err != nil || !strings.Contains(out, "STATE") {
		fmt.Printf("  [!] register service %s failed: %s\n", name, strings.TrimSpace(out))
		return
	}
	// Correct a start type that was changed by security software / policy (Disabled will prevent Gen2 from ever starting).
	// The start type is in 'sc qc', not in 'query'; status (STOPPED/RUNNING) is in 'query'.
	start := "demand"
	if qc, qerr := hxcore.RunOut("sc.exe", "qc", name); qerr == nil {
		qcu := strings.ToUpper(qc)
		switch {
		case strings.Contains(qcu, "DISABLED"):
			hxcore.RunOut("sc.exe", "config", name, "start=", "demand")
			start = "demand (was changed to DISABLED, corrected)"
		case strings.Contains(qcu, "AUTO_START"):
			start = "auto (WARNING: should be demand)"
		}
	}
	stateS := "?"
	switch {
	case strings.Contains(out, "RUNNING"):
		stateS = "RUNNING"
	case strings.Contains(out, "STOPPED"):
		stateS = "STOPPED"
	}
	fmt.Printf("  service %s registered (%s, %s); loaded by the SYSTEM task after logon\n", name, start, stateS)
}

// ensureSvcLoaded: ensure the driver service is registered and loaded.
// v2.4.6: 'sc start' only has permission when called by the SYSTEM task (or manually as administrator);
// failure under normal user permissions (Run-key fallback) is expected - silently handed off to the SYSTEM task.

// throttleStopAppRunning: detects whether the local ThrottleStop software's process is running (when a third party occupies the driver, self-clean is skipped).

func throttleStopAppRunning() bool {
	out, _ := hxcore.RunOut("tasklist.exe", "/FI", "IMAGENAME eq ThrottleStop.exe")
	return strings.Contains(out, "ThrottleStop.exe")
}

// redeployDriverFile: v2.6.0 - antivirus may delete driver files; before each -gen2 re-extract from embed
// to System32\drivers (skip the write if content matches, to avoid in-use conflicts). Returns true = driver file is ready.

func redeployDriverFile(sysFile string) bool {
	data, err := embedded.ReadFile("embed/" + sysFile)
	if err != nil {
		return false
	}

	target := os.Getenv("SystemRoot") + "\\System32\\drivers\\" + sysFile
	if cur, cerr := os.ReadFile(target); cerr == nil && len(cur) == len(data) {
		return true
	}
	if werr := os.WriteFile(target, data, 0o644); werr != nil {
		return false
	}
	return true
}





func ensureSvcLoaded(name string, sysFile string) {
	if out, _ := hxcore.RunOut("sc.exe", "query", name); strings.Contains(out, "RUNNING") {
		return // running
	}
	if redeployDriverFile(sysFile) {
		hxcore.AddDefenderExclusions()
	}
	bin := fmt.Sprintf("\\SystemRoot\\System32\\drivers\\%s", sysFile)
	hxcore.RunOut("sc.exe", "create", name, "type=", "kernel", "start=", "demand", "binPath=", bin)
	_, err := hxcore.RunOut("sc.exe", "start", name)
	if err != nil {
		// First start failed - common when antivirus deleted the driver file or the service config was changed to disabled.
		// Delete service -> redeploy -> retry once with a freshly created service.

		hxcore.RunOut("sc.exe", "delete", name)
		redeployDriverFile(sysFile)
		hxcore.RunOut("sc.exe", "create", name, "type=", "kernel", "start=", "demand", "binPath=", bin)
		if out, err := hxcore.RunOut("sc.exe", "start", name); err != nil {
			fmt.Printf("[Gen2] start service %s failed: %s\n", name, strings.TrimSpace(out))
			if !isAdmin() {
				fmt.Println("[Gen2] current user is not administrator - handed off to the SYSTEM scheduled task (no user action needed)")
			}
		}
	}
}

func setupBootEntry() error {
	// Idempotent: if a "50HX Unlock" entry already exists, skip (use the full firmware enum; the description is in each entry's detail)
	if out, _ := hxcore.RunOut("bcdedit.exe", "/enum", "firmware"); strings.Contains(out, bootDesc) {
		fmt.Println("    boot entry already exists, skipped")
		return nil
	}
	// 1. Copy {bootmgr} as a template
	out, err := hxcore.RunOut("bcdedit.exe", "/copy", "{bootmgr}", "/d", bootDesc)
	if err != nil {
		return fmt.Errorf("bcdedit copy: %v", err)
	}
	re := regexp.MustCompile(`\{([0-9a-fA-F-]{36})\}`)
	m := re.FindStringSubmatch(out)
	if len(m) < 2 {
		return errors.New("could not parse bcdedit output: " + out)
	}
	guid := m[1]
	cleanup := func() { hxcore.RunOut("bcdedit.exe", "/delete", "{"+guid+"}", "/f") }

	// 2. Find the ESP drive letter (remount via mountvol)
	esp := hxcore.MountESP()
	if esp == "" {
		cleanup()
		return errors.New("could not mount the ESP")
	}
	defer hxcore.UnmountESP(esp)

	// 3. set device + path
	if _, err := hxcore.RunOut("bcdedit.exe", "/set", "{"+guid+"}", "device", "partition="+esp+":"); err != nil {
		cleanup()
		return err
	}
	path := efiDir + "\\" + efiFile // \EFI\50HX\50HXUNLK.EFI
	if _, err := hxcore.RunOut("bcdedit.exe", "/set", "{"+guid+"}", "path", path); err != nil {
		cleanup()
		return err
	}
	// 4. displayorder addfirst
	if _, err := hxcore.RunOut("bcdedit.exe", "/set", "{fwbootmgr}", "displayorder", "{"+guid+"}", "/addfirst"); err != nil {
		cleanup()
		return err
	}
	fmt.Printf("    boot entry %s promoted to first\n", guid)
	return nil
}

func setRunKey() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Println("  [!] Could not get exe path:", err)
		return
	}
	abs, _ := filepath.Abs(exe)
	val := fmt.Sprintf("\"%s\" -gen2 -silent", abs)
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		k, _, err = registry.CreateKey(registry.CURRENT_USER,
			`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	}
	if err != nil {
		fmt.Println("  [!] Run-key write failed:", err)
		return
	}
	defer k.Close()
	if err := k.SetStringValue("50HXGen2", val); err != nil {
		fmt.Println("  [!] Run-key set failed:", err)
		return
	}
	// Note: this is only the HKCU Run key (auxiliary channel, tries at logon); the SYSTEM scheduled task is the authoritative channel.
	// Do not print "Gen2 registered" so the success hint from setupGen2Task below is not confused.
	fmt.Println("  Gen2 Run key written (HKCU, tries at logon; SYSTEM task is the authoritative channel): " + abs)
}

// setupGen2Task: v2.4.6 core - register a SYSTEM scheduled task that, at logon (delayed 30s),
// silently runs -gen2 with maximum permissions.
//
// Why it is needed: the driver service is demand-start; after logon it must be brought up via 'sc start',
// and 'sc start' requires Administrator. The Run key runs with normal user permissions ->
// "OpenService failed 5: Access is denied" -> the driver never starts -> Gen2 always fails
// (the real root cause of community issues #1 and #2).
// Why not use UAC elevation: a UAC popup at every logon is a poor UX, and silent-elevation-disabled
// UAC would still fail with downgraded permissions.
// SYSTEM task = silent administrator: highest permissions, no popup, timing still after logon (safe).
// Keep demand: switching to auto would load the driver early in boot and contend with nvlddmkm for BAR0
// (historically observed code 19 / abnormal startup); demand + load-after-logon is the verified timing.
//
// v2.6.0: changed to return an error; after creation, double-check with hxcore.TaskInfo that the task really exists
// (previously schtasks returning success was taken as done, so user-side "task not registered" was only exposed when Gen2 did not run);
// failed -> automatic retry; still failed -> return an error, and the caller pops up the -task repair command.
//
// v2.6.0 fix (root cause of the false report "installed without admin yet it says not registered, and reboot does auto-unlock"):
// schtasks /create exit code 0 means the task was submitted to the Task Scheduler service (real success).
//
// The authoritative verdict must be, and only be, "exit code 0". It cannot rely on the "SUCCESS/success" string in stdout:
//  - On Chinese-Windows, "success" is emitted by schtasks using the system ANSI/GBK code page, but Go treats
//    the pipe bytes as UTF-8; the literal "success" (UTF-8) does not match the GBK bytes -> Contains fails.
//  - In some environments schtasks /create's stdout is even empty (success info goes elsewhere), so there is nothing to match.
//  - The previous dependency on the "SUCCESS/success" string led to false negatives - reliably reproduced on Chinese machines as "false failure".
// Exit code 0 means the task is written to the scheduler service; this is language / code-page-independent and is the reliable verdict.
// (The follow-up /query still suffers from a submit-delay race and is used only as optional information, not as the pass/fail criterion.)
func setupGen2Task() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not get exe path: %v", err)
	}
	abs, _ := filepath.Abs(exe)
	tn := gen2TaskName
	var lastErr string
	for attempt := 1; attempt <= 3; attempt++ {
		out, cerr := hxcore.RunOut("schtasks.exe", "/create", "/tn", tn,
			"/tr", fmt.Sprintf("\"%s\" -gen2 -silent -guard", abs),
			"/sc", "onlogon", "/ru", "SYSTEM", "/delay", "0000:30", "/f")
		// Authoritative verdict = exit code 0. The task is written to the scheduler service (the "SUCCESS/success" string is unreliable on Chinese machines - do not depend on it).
		// Only a non-zero exit code counts as a real failure; exit code 0 is always treated as success, with no second query (avoids false reports from the submit-delay race).
		if cerr == nil {
			fmt.Println("  Gen2 task registered (SYSTEM, logon delay 30s, silent): " + abs)
			return nil
		}
		lastErr = strings.TrimSpace(out)
		if attempt < 3 {
			fmt.Printf("  [!] task register failed (attempt %d), retrying... (%s)\n", attempt, lastErr)
			time.Sleep(800 * time.Millisecond)
		}
	}
	return fmt.Errorf("Gen2 scheduled task creation failed (after retries): %s\n      Manual workaround: run '50HXInstaller.exe -task' as administrator", lastErr)
}

// ===================== Gen2 unlock (native, no python) =====================

func gen2Main() {
	// Idempotent; in -silent (called by logon auto-start) the entire run is window-less and silent
	// v2.5: BYOVD (ThrottleStop + WinRing0) - no test signing required; remove-when-done (self-clean)

	// v2.6.0: single-instance mutex - prevents two processes (SYSTEM task / Run key / manual -gen2 triggered concurrently)
	// from both doing 'sc start' on the same driver and contending for BAR0, which would corrupt link / driver state.
	// Placed first: if the lock cannot be acquired, exit immediately; never enter the driver-load critical section.
	owned, release := gen2AcquireSingleInstance()
	if !owned {
		fmt.Println("[Gen2] Another Gen2 instance is running, skipped (single-instance protection)")
		hxcore.WriteGen2Status("Skipped: another Gen2 instance is running (single-instance protection, to avoid concurrent driver contention)")
		return
	}
	defer release()

	// v2.6.0: timing protection - wait until nvlddmkm enters RUNNING before touching the GPU.
	// Retraining before the NV driver initialises will cause the driver (once up) to reset the PCIe link /
	// overwrite GPU registers, which both wipes out Gen2 and can trigger code 19 (Installer comment around
	// line 785 documented "retraining while nvlddmkm still owns the GPU leads to abnormal state").
	// On normal machines nvlddmkm reaches RUNNING within a few seconds of logon -> almost no wait here;
	// on slow / multi-GPU machines it waits until ready, eliminating the brittleness of a fixed 30s delay.
	waitForNvDriver(60 * time.Second)

	ensureGspSilent()
	defer cleanupByovd() // registered first -> runs last (after handle Close); also runs on failure

	// The driver files may have been deleted by the previous remove-when-done; re-extract from embed each time
	sysDir := os.Getenv("SystemRoot") + "\\System32\\drivers"
	for _, df := range []string{"ThrottleStop.sys", "WinRing0x64.sys"} {
		if _, err := os.Stat(filepath.Join(sysDir, df)); err != nil {
			copyEmbedTo(filepath.Join(sysDir, df), df) // ignore errors when the file is in use
		}
	}
	ensureSvcLoaded("ThrottleStop", "ThrottleStop.sys")
	ensureSvcLoaded("WinRing0_1_2_0", "WinRing0x64.sys")

	th, err := hxcore.OpenThrottleStop()
	if err != nil {
		if !isAdmin() {
			fmt.Println("[Gen2] ThrottleStop is not loaded and the current user is not administrator - handed off to the SYSTEM task, silent exit")
			gen2StatusFail("ThrottleStop driver not loaded (SYSTEM task is responsible for starting it)")
			return
		}
		fmt.Println("[Gen2] ThrottleStop driver is not running. Please re-run the installer (as administrator) and reboot.")
		gen2StatusFail("ThrottleStop driver not running (requires administrator to re-run the installer)")
		gen2Notify("ThrottleStop driver not running.\nPossible causes: 1) antivirus quarantined ThrottleStop.sys (this tool adds Defender exclusions; for third-party antivirus please allow it in the Security Center); 2) a local ThrottleStop installation is occupying or conflicting with the driver (disable ThrottleStop and retry; this tool will reuse it automatically).\nPlease right-click the installer -> Run as administrator, then reboot.")
		return
	}
	// The th/wh handles may be reopened during the -hard fallback (Stage2); the deferred close below uses the final values.

	wh, err := hxcore.OpenDevice(`\\.\WinRing0_1_2_0`)
	if err != nil {
		if !isAdmin() {
			fmt.Println("[Gen2] WinRing0 is not loaded and the current user is not administrator - handed off to the SYSTEM task, silent exit")
			gen2StatusFail("WinRing0 driver not loaded, and the current user has normal permissions (SYSTEM task is responsible for starting it)")
			return
		}
		fmt.Println("[Gen2] WinRing0 driver is not running.")
		gen2StatusFail("WinRing0 driver not running (requires administrator to re-run the installer)")
		gen2Notify("WinRing0 driver not running.\nPossible causes: 1) antivirus quarantined WinRing0x64.sys (this tool adds Defender exclusions; for third-party antivirus please allow it in the Security Center); 2) a local ThrottleStop installation is occupying or conflicting with the driver (disable ThrottleStop and retry; this tool will reuse it automatically).\nPlease right-click the installer -> Run as administrator, then reboot.")
		return
	}
	// Deferred close uses the final values of th/wh (supports reopening handles during the -hard fallback)
	defer func() { hxcore.CloseHandle(th); hxcore.CloseHandle(wh) }()

	// Locate the 50HX (VEN_10DE&DEV_1E09); do not hard-code the BDF.
	// v2.6.0: slow GPU initialisation (the 50HX not yet ready at boot) can occasionally cause location failure ->
	// retry up to 3 times, to avoid "false failure" causing this boot session to not unlock (the SYSTEM task at +30s will confirm again).
	var gpuBDF uint32
	gpuFound := false
	for attempt := 1; attempt <= 3; attempt++ {
		gpuBDF, gpuFound = hxcore.FindGPUPCI(wh)
		if gpuFound {
			break
		}
		if attempt < 3 {
			fmt.Printf("[Gen2] 50HX not yet located, retrying in 2s (%d/3)...\n", attempt)
			time.Sleep(2 * time.Second)
		}
	}
	if !gpuFound {
		fmt.Println("[Gen2] Could not locate 50HX (VEN_10DE&DEV_1E09). Please send the log.")
		gen2StatusFail("Could not locate 50HX (VEN_10DE&DEV_1E09) on the PCI bus")
		gen2Notify("Could not find 50HX on the PCI bus.\nPlease confirm the GPU is seated and the driver is installed.")
		return
	}
	gpuBus := (gpuBDF >> 8) & 0xFF
	fmt.Printf("[Gen2] 50HX is at %02x:%02x.%x\n", gpuBus, (gpuBDF>>3)&0x1F, gpuBDF&7)
	cur := hxcore.LinkSpeed(wh, gpuBDF)
	fmt.Printf("[Gen2] current link: Gen%d\n", cur)
	// v2.6.0: record the raw PCIe registers (LNKCAP/LNKCTL/LNKCTL2) - community feedback for -hard debugging
	if cap := hxcore.PcieCap(wh, gpuBDF); cap != 0 {
		rd := func(off uint32) uint32 {
			v, _ := hxcore.PciRd(wh, gpuBDF, off)
			return v
		}
		fmt.Printf("[Gen2] LNKCAP=0x%08X LNKCTL=0x%08X LNKCTL2=0x%08X (target Gen%d)\n",
			rd(cap+0x0C), rd(cap+0x10), rd(cap+0x30), rd(cap+0x30)&0xF)
	}
	if cur >= 2 {
		fmt.Println("[Gen2] Already at Gen2, no action required.")
		hxcore.WriteGen2Status(fmt.Sprintf("OK Gen2, no action required: current link is Gen%d\nrun identity: %s\n50HX location: %02x:%02x.%x\n",
			cur, map[bool]string{true: "administrator/SYSTEM", false: "normal user (limited)"}[isAdmin()],
			gpuBus, (gpuBDF>>3)&0x1F, gpuBDF&7))
		gen2Notify("PCIe is Gen" + fmt.Sprint(cur) + ", no action required.")
		return
	}

	// 1. PL0 writes (BAR0) - via ThrottleStop physical-memory writes
	fmt.Println("[Gen2] Writing XVE / link registers (ThrottleStop)...")
	pl0 := []struct {
		off  uint64
		val  uint32
		name string
	}{
		{0x8872C, 0x6, "XVE_OVR=6"},
		{0x8C040, 0x80085800, "LINK_CONFIG_0"},
		{0x8841C, 0xE0B42D00, "PRIV_MISC_1"},
		{0x8C2C0, 0x068731B3, "CYA_0"},
	}
	bar0raw, _ := hxcore.PciRd(wh, gpuBDF, 0x10)
	if bar0raw == 0 || bar0raw == 0xFFFFFFFF {
		bar0raw = 0xF6000000
	}
	bar0Phys := uint64(bar0raw & 0xFFFFFFF0)
	fmt.Printf("[Gen2] BAR0 = 0x%08X\n", bar0Phys)
	// v2.6.0: BAR0 validity check - before writing PL0, confirm that BAR0 truly points at the 50HX MMIO so the 4
	// link registers are not written to the wrong physical address (multi-GPU / cheap-board BAR remap, BAR0 read-back abnormal scenarios).
	// NV_PMC BOOT_0 @ BAR0+0x0: TU106 family byte = 0x16 (unlock40x_v70.c:2555 records 40HX=0x166000A1).
	// Family mismatch or read-back 0xFFFFFFFF -> abort PL0 write (prefer to not unlock this session rather than pollute another device's MMIO).
	boot0, berr := hxcore.TSRead(th, bar0Phys+0x0)
	if berr != nil || (boot0&0xFF000000) != 0x16000000 {
		fmt.Printf("[Gen2][!] BAR0 validity check failed: BOOT_0=0x%08X (expected TU10x family 0x16xxxxxx); aborted PL0 write\n", boot0)
		gen2StatusFail(fmt.Sprintf("BAR0 check failed (BOOT_0=0x%08X), safely aborted PL0 write; please send the log", boot0))
		if !hasArg("-silent") {
			gen2Notify("BAR0 check failed; Gen2 safely aborted.\nPlease send the log.")
		}
		return
	}
	fmt.Printf("[Gen2] BAR0 check passed (BOOT_0=0x%08X, TU106)\n", boot0)
	for _, p := range pl0 {
		if werr := hxcore.TSWrite(th, bar0Phys+p.off, p.val); werr != nil {
			fmt.Printf("  [!] %s write failed: %v\n", p.name, werr)
			continue
		}
		if rb, rerr := hxcore.TSRead(th, bar0Phys+p.off); rerr != nil || rb != p.val {
			fmt.Printf("  [warn] %s read-back 0x%08x (expected 0x%08x)\n", p.name, rb, p.val)
		} else {
			fmt.Printf("  %s OK (0x%08X)\n", p.name, rb)
		}
	}

	// 2. LNKCTL2 TLS=2 (GPU + root)
	root := hxcore.FindRootPort(wh, gpuBus)
	if root == 0xFFFFFFFF {
		fmt.Println("[Gen2] root port not found, using GPU retrain fallback")
	}
	fmt.Printf("[Gen2] root port = 00:%02x.%x\n", (root>>3)&0x1F, root&7)
	for _, b := range []struct {
		bdf uint32
		tag string
	}{{gpuBDF, "GPU"}, {root, "ROOT"}} {
		if b.bdf == 0xFFFFFFFF {
			continue
		}
		cap := hxcore.PcieCap(wh, b.bdf)
		if cap == 0 {
			continue
		}
		// v2.6.0: read-modify-write - only change TLS (bits 3:0), preserve the rest (matches the python version).
		// Previously the direct write of {2,0} cleared the upper 12 bits; some VBIOS depend on them, causing link abnormalities.
		curRaw, _ := hxcore.PciRd(wh, b.bdf, cap+0x30)
		nv := uint16(curRaw&0xFFF0) | 2
		hxcore.PciWr(wh, b.bdf, cap+0x30, []byte{byte(nv), byte(nv >> 8)})
		rb, _ := hxcore.PciRd(wh, b.bdf, cap+0x30)
		fmt.Printf("  %s LNKCTL2 TLS=2 (0x%04X -> 0x%04X, read-back TLS=%d)\n", b.tag, curRaw&0xFFFF, rb&0xFFFF, rb&0xF)
	}

	// 3. UPGRADE retrain: clear bit -> set bit pulse (setting the bit alone does not work on the 50HX)
	retrain := func(bdf uint32) {
		cap := hxcore.PcieCap(wh, bdf)
		if cap == 0 {
			return
		}
		ctl, _ := hxcore.PciRd(wh, bdf, cap+0x10)
		lo := uint16(ctl & 0xFFFF)
		buf := []byte{byte(lo & 0xFF), byte((lo >> 8) & 0xFF)}
		buf[0] &^= 0x20 // clear bit5
		hxcore.PciWr(wh, bdf, cap+0x10, buf)
		time.Sleep(300 * time.Millisecond)
		ctl2, _ := hxcore.PciRd(wh, bdf, cap+0x10)
		lo2 := uint16(ctl2 & 0xFFFF)
		buf2 := []byte{byte(lo2 & 0xFF), byte((lo2 >> 8) & 0xFF)}
		buf2[0] |= 0x20 // set bit5
		hxcore.PciWr(wh, bdf, cap+0x10, buf2)
	}
	// v2.6.0: single root retrain -> up to 6 alternating root/GPU rounds (matches the python version, more stable than the original 4 rounds).
	// On cheap boards / dual-GPU systems, a single root pulse often fails to retrain (issue #8 "needs repeated disable/enable"),
	// alternating rounds significantly improve success; once Gen2 is achieved, exit early (capped at ~13s, runs only after a 30s post-logon delay).
	for attempt := 0; attempt < 6; attempt++ {
		bdf, tag := gpuBDF, "GPU"
		if attempt%2 == 0 && root != 0xFFFFFFFF {
			bdf, tag = root, "ROOT"
		}
		fmt.Printf("[Gen2] Link retrain #%d (%s end)...\n", attempt+1, tag)
		retrain(bdf)
		time.Sleep(2200 * time.Millisecond)
		cur = hxcore.LinkSpeed(wh, gpuBDF)
		if cur >= 2 {
			break
		}
	}

	// v2.6.0: verdict correction - drivers/ASPM will downshift the link to Gen1 when idle; only looking at the current
	// speed would misreport success as failure (one source of the community's "Gen1" misreports, confirmed in the v2.4.5 era:
	// "idle power saving shows Gen1; under load the link automatically runs at full Gen2"). Distinguish via the GPU's LNKCTL2
	// TLS (target speed): TLS>=2 and current Gen1 = config success; idle downshift is normal.
	tls := uint32(0)
	if gcap := hxcore.PcieCap(wh, gpuBDF); gcap != 0 {
		if v, rerr := hxcore.PciRd(wh, gpuBDF, gcap+0x30); rerr == nil {
			tls = v & 0xF
		}
	}
	// v2.5.2: Stage2 automation (community #11/#20/#8 plus empirically demonstrated solutions on multiple platforms on the forum) -
	// on cheap boards / multi-GPU / X99 platforms, retrain-only cannot train up at boot; a Root Link Disable (+ PnP restore)
	// is required to reach Gen2, and must be repeated each boot (#20 confirmed); manual -hard users will never do it,
	// and the widespread "disable/re-enable the GPU manually each boot" workarounds on the forum all stem from this.
	// Now the logon task automatically runs Stage2 once when Stage1 does not achieve Gen2 (cur<2) (silent, capped at ~1 minute):
	//   - Regardless of TLS: if TLS is configured but the link is still Gen1 -> LD will immediately train up and remove the "idle downshift" ambiguity;
	//     if TLS is not set -> rewriting after LD often sticks (the .06 batch forum users also succeed after LD;
	//     instructions for "write-protected batches" and "retrain-only is not enough" were previously conflated).
	//   - Opt-out: reg add HKLM\SOFTWARE\50HXUnlock /v Gen2AutoHard /t REG_DWORD /d 0 /f
	//     (machines where 50HX is the only display card and a few seconds of black screen after logon is not desired can disable it)
	//   - Manual -hard kept: cur<2 forces this path (no longer requires tls>=2).
	// During Link Disable nvidia-smi briefly reports "GPU is lost"; automatic PnP restore runs afterwards.
	if cur < 2 && (hasArg("-hard") || gen2AutoHardEnabled()) {
		if hasArg("-hard") {
			fmt.Println("[Gen2] retrain did not succeed -> -hard explicitly triggers Link Disable fallback")
		} else {
			fmt.Println("[Gen2] retrain did not succeed -> automatically running Link Disable fallback (Gen2AutoHard is enabled by default; see README section 2.5 to disable)")
		}
		gen2HardFallback(&th, &wh, gpuBDF, bar0Phys, root)
		return
	}
	gen2Verdict := ""
	unlocked := false
	switch {
	case cur >= 2:
		unlocked = true
		fmt.Printf("[Gen2] *** GEN2 ACHIEVED (Gen%d) ***\n", cur)
		gen2Verdict = fmt.Sprintf("OK Gen2 success: current link Gen%d", cur)
	case tls >= 2:
		unlocked = true
		fmt.Printf("[Gen2] TLS=Gen%d but current Gen%d - idle power saving downshift (under load the link automatically returns to Gen2)\n", tls, cur)
		gen2Verdict = fmt.Sprintf("OK Gen2 configured (TLS=Gen%d): current Gen%d is idle power saving downshift; under load it automatically returns to Gen2", tls, cur)
	default:
		fmt.Printf("[Gen2] still at Gen%d (TLS=Gen%d), unlock failed. Please send the log.\n", cur, tls)
		gen2Verdict = fmt.Sprintf("FAIL Gen2: still at Gen%d (TLS=Gen%d; all PL0 writes OK but TLS not sticking, usually because the driver/GSP is holding the link policy - the registered logon task will automatically run the Stage2 fallback; if the task is not registered it will not auto-run, register it then retry; see README section 5.2)", cur, tls)
	}
	// v2.6.0: on success clear any leftover retry task; on failure schedule an automatic retry per policy (see hxcore config for count / interval).
	// v3.0.1: resident-guardian mode does not preclude the one-shot retry task - the guardian process retries every minute.
	if unlocked {
		deleteGen2Retry()
	} else if hxcore.DriverStrategy() != hxcore.DriverStrategyResident {
		scheduleGen2Retry(retryDepth())
	}
	st := fmt.Sprintf("Verdict: %s\nrun identity: %s\n50HX location: %02x:%02x.%x\nRoot Port: %02x:%02x.%x\n"+
		"Link: current Gen%d / target TLS=Gen%d\ndrivers: ThrottleStop=OK WinRing0=OK (BYOVD, remove-when-done)\n",
		gen2Verdict,
		map[bool]string{true: "administrator/SYSTEM", false: "normal user (limited)"}[isAdmin()],
		gpuBus, (gpuBDF>>3)&0x1F, gpuBDF&7,
		(root>>8)&0xFF, (root>>3)&0x1F, root&7,
		cur, tls)
	if wErr := hxcore.WriteGen2Status(st); wErr != nil {
		fmt.Printf("[Gen2] status file write failed (does not affect unlock): %v\n", wErr)
	}
	if !hasArg("-silent") && !hasArg("-y") {
		icon := uint(mbIconInfo)
		txt := fmt.Sprintf("PCIe link: current Gen%d (target TLS=Gen%d)\n", cur, tls)
		if unlocked {
			txt += "=== GEN2 UNLOCK SUCCESS ==="
			if cur < 2 {
				txt += "\n(current is idle power saving downshift; under load the link automatically returns to Gen2)"
			}
		} else {
			txt += "still at Gen1, unlock failed (see log)."
			icon = mbIconError
		}
		msgbox("50HX Gen2", txt, icon)
	}
}

// ---------- v3.0.1: resident guardian (started by the logon task with -guard when the driver policy is resident) ----------
// Every 1 minute, read the GPU target speed TLS: if TLS>=2 leave it alone (idle downshift to Gen1 is normal power saving);
// if TLS falls back below <2 the unlock configuration was lost (e.g. GPU reset / driver reloaded) -> automatically re-run a full unlock.
// The process stays resident with the logon task; logoff / task end / uninstall stops it. The guardian retry does not preclude the one-shot retry task.
const gen2GuardInterval = 1 * time.Minute

func residentGuard() {
	fmt.Println("[guardian] resident guardian started: every 1 minute checks the Gen2 target (TLS); if the configuration is lost (TLS<2) it automatically retrains; stops on logoff or task end.")
	for {
		time.Sleep(gen2GuardInterval)
		st := hxcore.ReadUnlockStateV2(0, 0)
		if st.TLS >= 2 {
			continue // target still in place: idle downshift is normal, leave it alone
		}
		fmt.Println("[guardian] Detected TLS<2 - Gen2 unlock configuration lost, automatically re-running unlock...")
		gen2Main()
	}
}

// ---------- Gen2 -hard fallback: Root Link Disable + PnP restore (Stage 2) ----------
// Entered only when explicitly running '50HXInstaller.exe -gen2 -hard'. Normal / scheduled-task paths never trigger it,
// because Root Link Disable causes nvidia-smi to briefly report "GPU is lost" (instant link drop + driver reset).
// Aligned with community byovd.py (member573, issue #11, 2026-09-06 multi-GPU testing):
//   retrain-only is not enough on cheap boards / multi-GPU -> a Root Link Disable loop (PL0 + TLS held) makes
//   LNKCAP.max=2 train up to Gen2 -> PnP disable/enable the 50HX to restore "GPU is lost" ->
//   Retrain-ONLY (no second LD, to keep driver health) -> restart NVDisplay.ContainerLocalSystem.
// The code layer cannot tell whether "current Gen1" is an idle downshift or a true failed train, so -hard is left to manual judgement.

func gen2WritePL0(th syscall.Handle, bar0Phys uint64) {
	pl0 := []struct {
		off  uint64
		val  uint32
		name string
	}{
		{0x8872C, 0x6, "XVE_OVR=6"},
		{0x8C040, 0x80085800, "LINK_CONFIG_0"},
		{0x8841C, 0xE0B42D00, "PRIV_MISC_1"},
		{0x8C2C0, 0x068731B3, "CYA_0"},
	}
	for _, p := range pl0 {
		if werr := hxcore.TSWrite(th, bar0Phys+p.off, p.val); werr != nil {
			fmt.Printf("  [!] %s write failed: %v\n", p.name, werr)
			continue
		}
		if rb, rerr := hxcore.TSRead(th, bar0Phys+p.off); rerr != nil || rb != p.val {
			fmt.Printf("  [warn] %s read-back 0x%08x (expected 0x%08x)\n", p.name, rb, p.val)
		} else {
			fmt.Printf("  %s OK (0x%08X)\n", p.name, rb)
		}
	}
}

// 16-bit LNKCTL2 TLS write (read-modify-write bits 3:0 only, preserve the rest)
func gen2SetTLS(wh syscall.Handle, bdf uint32, tls uint16) {
	if bdf == 0xFFFFFFFF {
		return
	}
	cap := hxcore.PcieCap(wh, bdf)
	if cap == 0 {
		return
	}
	cur, _ := hxcore.PciRd(wh, bdf, cap+0x30)
	nv := uint16(cur&0xFFF0) | (tls & 0xF)
	_ = hxcore.PciWr(wh, bdf, cap+0x30, []byte{byte(nv), byte(nv >> 8)})
	rb, _ := hxcore.PciRd(wh, bdf, cap+0x30)
	fmt.Printf("    TLS=%d write LNKCTL2 (0x%04X -> 0x%04X, read-back TLS=%d)\n", tls, cur&0xFFFF, rb&0xFFFF, rb&0xF)
}

// 16-bit LNKCTL retrain pulse (bit5)
func gen2RetrainPulse(wh syscall.Handle, bdf uint32) {
	if bdf == 0xFFFFFFFF {
		return
	}
	cap := hxcore.PcieCap(wh, bdf)
	if cap == 0 {
		return
	}
	ctl, _ := hxcore.PciRd(wh, bdf, cap+0x10)
	lo := uint16(ctl & 0xFFFF)
	buf := []byte{byte(lo & 0xFF), byte((lo >> 8) & 0xFF)}
	buf[0] &^= 0x20 // clear bit5
	_ = hxcore.PciWr(wh, bdf, cap+0x10, buf)
	time.Sleep(300 * time.Millisecond)
	ctl2, _ := hxcore.PciRd(wh, bdf, cap+0x10)
	lo2 := uint16(ctl2 & 0xFFFF)
	buf2 := []byte{byte(lo2 & 0xFF), byte((lo2 >> 8) & 0xFF)}
	buf2[0] |= 0x20 // set bit5
	_ = hxcore.PciWr(wh, bdf, cap+0x10, buf2)
}

// Root Link Disable loop (PL0 + TLS held) - makes LNKCAP.max=2 train up to Gen2
func gen2RootLinkDisable(th syscall.Handle, wh *syscall.Handle, gpuBDF uint32, bar0Phys uint64, root uint32) {
	if root == 0xFFFFFFFF {
		fmt.Println("    [warn] no root port, skipped Link Disable")
		return
	}
	cap := hxcore.PcieCap(*wh, root)
	if cap == 0 {
		fmt.Println("    [warn] root has no PCIe cap, skipped Link Disable")
		return
	}
	ctl, _ := hxcore.PciRd(*wh, root, cap+0x10)
	fmt.Printf("    ROOT Link Disable (ctl=0x%04X)\n", ctl&0xFFFF)
	lo := uint16(ctl & 0xFFFF)
	set := lo | 0x10 // bit4 = Link Disable
	_ = hxcore.PciWr(*wh, root, cap+0x10, []byte{byte(set), byte(set >> 8)})
	time.Sleep(500 * time.Millisecond)
	// PL0 + TLS held while the link is down
	gen2WritePL0(th, bar0Phys)
	gen2SetTLS(*wh, root, 2)
	gen2SetTLS(*wh, gpuBDF, 2)
	// clear bit4 -> retrain
	ctl2, _ := hxcore.PciRd(*wh, root, cap+0x10)
	clr := uint16(ctl2&0xFFFF) &^ 0x10
	_ = hxcore.PciWr(*wh, root, cap+0x10, []byte{byte(clr), byte(clr >> 8)})
	time.Sleep(2000 * time.Millisecond)
}

// PnP disable/enable 50HX - restores "GPU is lost" after Link Disable (nvidia-smi / GPU-Z disconnect)
func gen2PnpRecover40HX() bool {
	ps := `$iid=(Get-PnpDevice -Class Display | Where-Object { $_.InstanceId -match 'DEV_1E09' } | Select-Object -First 1).InstanceId; ` +
		`if($iid){ Disable-PnpDevice -InstanceId $iid -Confirm:$false; Start-Sleep -Seconds 2; ` +
		`Enable-PnpDevice -InstanceId $iid -Confirm:$false; Start-Sleep -Seconds 4; Write-Output "PnP-OK $iid" } ` +
		`else { Write-Output 'PnP-NONE' }`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
	fmt.Printf("    PnP restore: %s (err=%v)\n", strings.TrimSpace(string(out)), err)
	return err == nil && strings.Contains(string(out), "PnP-OK")
}

// Restart NVDisplay container (restore GPU-Z / Task Manager display, often needed after Link Disable)
func gen2RestartNVDisplay() {
	ps := `Restart-Service NVDisplay.ContainerLocalSystem -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
	fmt.Printf("    NVDisplay container restart: %s (err=%v)\n", strings.TrimSpace(string(out)), err)
}

// During -hard fallback PnP triggers a GPU reset, old \\.\ThrottleStop / WinRing0 handles may be invalidated -> reopen
func gen2ReopenDrivers(th, wh *syscall.Handle) bool {
	hxcore.CloseHandle(*th)
	hxcore.CloseHandle(*wh)
	ok := true
	if nt, e := hxcore.OpenThrottleStop(); e != nil {
		fmt.Printf("    [!] ThrottleStop reopen failed: %v\n", e)
		ok = false
	} else {
		*th = nt
	}
	if nw, e := hxcore.OpenDevice(`\\.\WinRing0_1_2_0`); e != nil {
		fmt.Printf("    [!] WinRing0 reopen failed: %v\n", e)
		ok = false
	} else {
		*wh = nw
	}
	return ok
}

// Restore GPU LNKCTL CCC (0x0140, Common Clock + Extended Synch) - keeps NVAPI / GPU-Z healthy
func gen2RestoreGPULnkctl(wh syscall.Handle, gpuBDF uint32) {
	cap := hxcore.PcieCap(wh, gpuBDF)
	if cap == 0 {
		return
	}
	ctl, _ := hxcore.PciRd(wh, gpuBDF, cap+0x10)
	cur := uint16(ctl & 0xFFFF)
	if (cur & 0x0140) != 0x0140 {
		want := (cur &^ 0x3) | 0x0140
		_ = hxcore.PciWr(wh, gpuBDF, cap+0x10, []byte{byte(want), byte(want >> 8)})
		rb, _ := hxcore.PciRd(wh, gpuBDF, cap+0x10)
		fmt.Printf("    GPU LNKCTL restore 0x%04X -> 0x%04X\n", cur, rb&0xFFFF)
	}
}

// Stage2 orchestration: LD -> retrain -> PnP restore -> retrain-only -> NVDisplay restart. Writes its own verdict.
func gen2HardFallback(th, wh *syscall.Handle, gpuBDF uint32, bar0Phys uint64, root uint32) {
	fmt.Println("\n[Gen2 -hard] === Link Disable fallback path (Stage 2) ===")
	fmt.Println("[Gen2 -hard] WARNING: this path causes nvidia-smi to briefly report 'GPU is lost' (instant link drop + driver reset),")
	fmt.Println("[Gen2 -hard] and after a few seconds PnP restore runs. Only use manually after confirming that retrain-only does not work on your hardware.")
	// BAR may be remapped after the link reset -> re-confirm BAR0
	if bar0raw, _ := hxcore.PciRd(*wh, gpuBDF, 0x10); bar0raw != 0 && bar0raw != 0xFFFFFFFF {
		bar0Phys = uint64(bar0raw & 0xFFFFFFF0)
	}
	fmt.Printf("[Gen2 -hard] BAR0 = 0x%08X\n", bar0Phys)
	didLD := false
	// 1. re-assert PL0
	gen2WritePL0(*th, bar0Phys)
	// 2. Root Link Disable loop
	if root != 0xFFFFFFFF {
		gen2RootLinkDisable(*th, wh, gpuBDF, bar0Phys, root)
		didLD = true
	}
	cur := hxcore.LinkSpeed(*wh, gpuBDF)
	fmt.Printf("[Gen2 -hard] After Link Disable: Gen%d\n", cur)
	// 3. Still Gen1 -> alternating retrain pulses for up to 6 rounds
	if cur < 2 {
		for i := 0; i < 6; i++ {
			// Community byovd.py: if retrain round 3 (i==2) is still Gen1, run one more Link Disable loop
			if i == 2 && cur < 2 && root != 0xFFFFFFFF {
				fmt.Println("[Gen2 -hard] retrain still failed -> second Link Disable loop")
				gen2RootLinkDisable(*th, wh, gpuBDF, bar0Phys, root)
			}
			gen2WritePL0(*th, bar0Phys)
			gen2SetTLS(*wh, root, 2)
			gen2SetTLS(*wh, gpuBDF, 2)
			bdf := gpuBDF
			tag := "GPU"
			if root != 0xFFFFFFFF && i%2 == 0 {
				bdf, tag = root, "ROOT"
			}
			fmt.Printf("[Gen2 -hard] retrain #%d (%s)...\n", i+1, tag)
			gen2RetrainPulse(*wh, bdf)
			time.Sleep(2200 * time.Millisecond)
			cur = hxcore.LinkSpeed(*wh, gpuBDF)
			if cur >= 2 {
				break
			}
		}
	}
	// 4. PnP restore "GPU is lost" + retrain-only + NVDisplay restart
	// v2.6.0: unconditionally restore whenever Link Disable was performed (previously only restored on success -
	// on failure the GPU would hang in the lost state, forcing the user to manually disable/enable in Device Manager, a common source of community complaints)
	if didLD {
		if cur >= 2 {
			fmt.Println("[Gen2 -hard] Trained to Gen2, running PnP restore + NVDisplay restart")
		} else {
			fmt.Println("[Gen2 -hard] Training did not succeed; still running PnP restore to ensure the GPU returns to a normal state")
		}
		gen2PnpRecover40HX()
		if !gen2ReopenDrivers(th, wh) {
			fmt.Println("[Gen2 -hard][!] driver reopen failed, aborted subsequent restore")
			gen2VerdictHard(gpuBDF, cur, false)
			return
		}
		time.Sleep(3000 * time.Millisecond)
		// retrain-only (no second LD)
		if bar0raw, _ := hxcore.PciRd(*wh, gpuBDF, 0x10); bar0raw != 0 && bar0raw != 0xFFFFFFFF {
			bar0Phys = uint64(bar0raw & 0xFFFFFFF0)
		}
		gen2WritePL0(*th, bar0Phys)
		gen2SetTLS(*wh, root, 2)
		gen2SetTLS(*wh, gpuBDF, 2)
		for i := 0; i < 6; i++ {
			cur = hxcore.LinkSpeed(*wh, gpuBDF)
			if cur >= 2 {
				break
			}
			bdf := gpuBDF
			if root != 0xFFFFFFFF && i%2 == 0 {
				bdf = root
			}
			gen2RetrainPulse(*wh, bdf)
			time.Sleep(2200 * time.Millisecond)
		}
		gen2RestoreGPULnkctl(*wh, gpuBDF)
		gen2RestartNVDisplay()
		cur = hxcore.LinkSpeed(*wh, gpuBDF)
		fmt.Printf("[Gen2 -hard] After PnP restore: Gen%d\n", cur)
	}
	gen2VerdictHard(gpuBDF, cur, cur >= 2)
}

func gen2VerdictHard(gpuBDF uint32, cur uint32, success bool) {
	// v2.6.0: same retry policy as Stage1 verdict - on success clear the retry task; on failure reschedule within the budget
	if success {
		deleteGen2Retry()
	} else {
		scheduleGen2Retry(retryDepth())
	}
	gpuBus := (gpuBDF >> 8) & 0xFF
	st := fmt.Sprintf("Verdict (Link Disable fallback): %s\n50HX location: %02x:%02x.%x\nLink: current Gen%d\ndrivers: ThrottleStop=OK WinRing0=OK (BYOVD, clean up per policy)\n",
		map[bool]string{true: "OK Gen2 success", false: "FAIL Gen2 (see log / post to community)"}[success],
		gpuBus, (gpuBDF>>3)&0x1F, gpuBDF&7, cur)
	if wErr := hxcore.WriteGen2Status(st); wErr != nil {
		fmt.Printf("[Gen2 -hard] status write failed: %v\n", wErr)
	}
	if !hasArg("-silent") && !hasArg("-y") {
		icon := uint(mbIconInfo)
		txt := fmt.Sprintf("Gen2 fallback: current Gen%d\n", cur)
		if success {
			txt += "=== GEN2 UNLOCK SUCCESS ==="
		} else {
			txt += "still at Gen1, fallback did not succeed (see log)."
			icon = mbIconError
		}
		msgbox("50HX Gen2", txt, icon)
	}
}

// ---------- v2.6.0: Gen2 automatic retry + Stage2 automatic fallback switch + policy config ----------

// retryDepth: current automatic retry depth (-retrydepth=N, 0=first run by the logon task)
func retryDepth() int {
	for _, a := range os.Args {
		if strings.HasPrefix(a, "-retrydepth=") {
			if n, err := strconv.Atoi(strings.TrimPrefix(a, "-retrydepth=")); err == nil && n > 0 {
				return n
			}
		}
	}
	return 0
}

// gen2AutoHardEnabled: switch for automatically running Stage2 (Link Disable + PnP restore); enabled by default.
// Disable: reg add HKLM\SOFTWARE\50HXUnlock /v Gen2AutoHard /t REG_DWORD /d 0 /f
// (machines where the 50HX is the only display card and a few seconds of black screen right after logon is not desired can disable it)
func gen2AutoHardEnabled() bool {
	return hxcore.ConfigInt("Gen2AutoHard", 1) != 0
}

// scheduleGen2Retry: after failure, schedule a one-shot automatic retry (SYSTEM, silent, default 15 minutes later).
// Overrides "slow driver/GSP ready after boot" / "link state just stuck" timing-style failures (community #12);
// 'depth' is the retry count; once the policy budget (Gen2RetryCount) is exceeded, no further retries are scheduled;
// the success path calls deleteGen2Retry.
func scheduleGen2Retry(depth int) {
	count, interval := hxcore.Gen2RetryPolicy()
	if depth >= count {
		fmt.Printf("[Gen2] automatic retry budget exhausted (%d/%d), waiting for next logon to try again\n", depth, count)
		return
	}
	t := time.Now().Add(time.Duration(interval) * time.Minute)
	if t.Day() != time.Now().Day() {
		fmt.Println("[Gen2] near midnight, skipping this session's retry schedule (a once-task crossing midnight is unreliable)")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	abs, _ := filepath.Abs(exe)
	out, err := hxcore.RunOut("schtasks.exe", "/create", "/tn", gen2RetryTask,
		"/tr", fmt.Sprintf("\"%s\" -gen2 -silent -retrydepth=%d", abs, depth+1),
		"/sc", "once", "/st", t.Format("15:04"), "/ru", "SYSTEM", "/f")
	if err != nil {
		fmt.Printf("[Gen2] retry task creation failed (does not affect unlock): %s\n", strings.TrimSpace(out))
		return
	}
	fmt.Printf("[Gen2] scheduled an automatic retry in %d minutes (%d/%d, task %s)\n", interval, depth+1, count, gen2RetryTask)
}

// deleteGen2Retry: after Gen2 succeeds, clean up any retry task that may exist
func deleteGen2Retry() {
	hxcore.RunOut("schtasks.exe", "/delete", "/tn", gen2RetryTask, "/f")
}

// gen2AcquireSingleInstance: v2.6.0 single-instance protection.
// Returns (whether exclusivity was acquired, release function). If not acquired = another instance is running, the caller should exit directly.
// Uses the kernel global mutex 'Global\50HXGen2SingleInstance': visible across users / sessions; if a process crashes, the kernel releases it automatically.
// More reliable than a file lock (which cannot stop two processes from simultaneously calling 'sc start' on the same service name).
func gen2AcquireSingleInstance() (bool, func()) {
	name, _ := windows.UTF16PtrFromString("Global\\50HXGen2SingleInstance")
	h, err := windows.CreateMutex(nil, true, name)
	if err != nil {
		// Could not create the mutex -> let it pass (better to run one extra time than to miss an unlock)
		fmt.Println("[Gen2] single-instance mutex creation failed, letting it pass:", err)
		return true, func() {}
	}
	if windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		_ = windows.CloseHandle(windows.Handle(h))
		return false, nil
	}
	return true, func() {
		_ = windows.ReleaseMutex(windows.Handle(h))
		_ = windows.CloseHandle(windows.Handle(h))
	}
}

// waitForNvDriver: v2.6.0 timing protection - must wait until nvlddmkm is actually RUNNING before touching the GPU.
// Retraining before the NV driver initialises will cause the driver (once up) to reset the PCIe link /
// overwrite GPU registers, which both wipes out Gen2 and can trigger code 19 (Installer comment around line 785).
// If the service does not exist (NV not installed), let it pass directly; if the 60s timeout is reached, continue anyway (does not block the unlock).
func waitForNvDriver(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		out, _ := hxcore.RunOut("sc.exe", "query", "nvlddmkm")
		if strings.Contains(out, "does not exist") || strings.Contains(out, "not installed") ||
			strings.Contains(out, "1060") {
			fmt.Println("[Gen2] nvlddmkm service not detected, skipping the wait and unlocking directly")
			return true
		}
		if strings.Contains(out, "RUNNING") {
			return true
		}
		if time.Now().After(deadline) {
			fmt.Printf("[Gen2] nvlddmkm did not enter RUNNING within %s (see log), continuing the unlock anyway\n", timeout)
			return false
		}
		fmt.Println("[Gen2] waiting for nvlddmkm to be ready...")
		time.Sleep(2 * time.Second)
	}
}

// cleanupByovd: v2.5 remove-when-done - stops and deletes the ThrottleStop / WinRing0 services and driver files.
// Runs at the end of gen2Main (via defers), so no third-party drivers are left in the system while gaming.
// v2.6.0: respect the driver run policy - the resident policy keeps the service and files (the GUI shows an anti-cheat risk hint).
func cleanupByovd() {
	if hxcore.DriverStrategy() == hxcore.DriverStrategyResident {
		fmt.Println("[Gen2] resident policy: keeping the driver service and files (the GUI / uninstaller can remove them)")
		return
	}
	appRunning := throttleStopAppRunning()
	for _, d := range []struct{ name, file string }{
		{"ThrottleStop", "ThrottleStop.sys"},
		{"WinRing0_1_2_0", "WinRing0x64.sys"},
	} {
		// If the local ThrottleStop software is using the driver -> do not delete (to avoid disrupting the user's software);
		// otherwise keep the "remove-when-done" behavior: stop service + delete service + delete files -> no kernel residency, no on-disk residue,
		// so anti-cheat (especially disk scanners like Vanguard) will not scan for vulnerable drivers while gaming.
		if appRunning {
			continue
		}
		hxcore.RunOut("sc.exe", "stop", d.name)
		hxcore.RunOut("sc.exe", "delete", d.name)
		os.Remove(filepath.Join(os.Getenv("SystemRoot")+"\\System32\\drivers", d.file))
	}
}

// gen2Notify: failure hint; in silent mode no popup
func gen2Notify(txt string) {
	if !hasArg("-silent") && !hasArg("-y") {
		msgbox("50HX Gen2", txt, mbIconError)
	}
}

// gen2StatusFail: v2.4.6 - writes the Gen2 not-run / failure reason into the status file,
// for 40HXCheck to display (the SYSTEM task in Session 0 cannot pop up dialogs for the user).
func gen2StatusFail(reason string) {
	ident := map[bool]string{true: "administrator/SYSTEM", false: "normal user (limited)"}[isAdmin()]
	hxcore.WriteGen2Status("FAIL Gen2 did not run: " + reason + "\nrun identity: " + ident + "\n")
}

// ===================== uninstall/status =====================

func uninstall() {
	if !isAdmin() {
		fmt.Println("[!] Administrator permissions are required.")
		msgbox("50HX Installer", "Administrator permissions are required.\nPlease right-click this program -> Run as administrator.", mbIconError)
		return
	}
	if lockOnce(`Local\40HXUninstaller_v1`) == nil {
		msgbox("50HX Installer", "The uninstall program is already running; please do not click again.", mbIconInfo)
		return
	}
	// v2.6.0 repair: all steps go through the hxcore components (same source as 50HXUninstaller.exe / GUI page 4).
	// Previously the inbuilt version only deleted the Run key + task + two old services, and the firmware boot entry
	// was located via '/enum {fwbootmgr}' - that output section has no per-entry description, so "50HX Unlock"
	// never matched ->
	// the boot entry could not be deleted; the EFI / GSP / driver files all remained, and after uninstall
	// the boot would still run the unlock.
	fmt.Println("=== Uninstall 50HX unlock (v3.0.0 component-level) ===")
	fmt.Print("[1/8] Delete scheduled task ... ")
	if rem := hxcore.UninstallTasks(); len(rem) > 0 {
		fmt.Println("done")
	} else {
		fmt.Println("not found (skipped)")
	}
	fmt.Print("[2/8] Delete Gen2 Run key ... ")
	hxcore.UninstallRunKey()
	fmt.Println("done")
	fmt.Print("[3/8] Delete firmware boot entry '50HX Unlock' ... ")
	if hxcore.UninstallBootEntry() {
		fmt.Println("done")
	} else {
		fmt.Println("not found (possibly removed already)")
	}
	fmt.Print("[4/8] Delete ESP unlock EFI ... ")
	if hxcore.UninstallEspEfi() {
		fmt.Println("done")
	} else {
		fmt.Println("not found / skipped")
	}
	fmt.Println("[5/8] Stop and delete driver services...")
	hxcore.UninstallDriverServices()
	fmt.Println("[6/8] Delete driver files...")
	hxcore.UninstallDriverFiles()
	fmt.Print("[6.5/8] Delete EnableGpuFirmware (restore GSP default-off) ... ")
	if hxcore.UninstallGspKey() {
		fmt.Println("done")
	} else {
		fmt.Println("not found (skipped)")
	}
	fmt.Print("[6.6/8] Clean up ProgramData + policy keys ... ")
	hxcore.UninstallProgramData()
	fmt.Println("done")
	fmt.Print("[6.7/8] Clean up Defender exclusions ... ")
	if err := hxcore.RemoveDefenderExclusions(); err != nil {
		fmt.Println("not run (ignorable):", err)
	} else {
		fmt.Println("done")
	}
	fmt.Println("[7/8] Check leftover...")
	left := hxcore.CheckLeftover()
	fmt.Println()
	fmt.Println("Uninstall done. Recommend rebooting the computer.")
	fmt.Println("  Note: power settings adjusted during install (Fast Startup / ASPM) are left untouched - see README section 2.4 for restore instructions.")
	icon := uint(mbIconInfo)
	txt := "Uninstall done.\nRecommend rebooting the computer.\n\nNote: power settings adjusted during install (Fast Startup / ASPM)\nare left untouched - they are a power preference; see README section 2.4 for restore instructions.\n"
	if len(left) > 0 {
		icon = mbIconError
		txt += "\nLeftover items:\n" + strings.Join(left, "\n")
	}
	txt += "\nDetailed log: " + filepath.Join(os.TempDir(), "50HX_installer.log")
	msgbox("50HX Installer", txt, icon)
}

func status() {
	fmt.Println("=== 50HX unlock status ===")
	gpuOK := hxcore.FindGPU()
	sb := hxcore.SecureBootOn()
	ts := hxcore.TestSigningOn()
	gs := hxcore.GspEnabled()
	fmt.Printf("GPU 50HX detection: %v\n", gpuOK)
	fmt.Printf("Secure Boot: %v\n", sb)
	fmt.Printf("Test signing: %v\n", ts)
	fmt.Printf("GSP enable (EnableGpuFirmware=1): %v\n", gs)
	// v2.4.1: GSP location diagnostics - disguised / modded drivers have AdapterString != "CMP 50HX"
	if sub, adapter, fw := hxcore.GspDiag(); sub != "" {
		fmt.Printf("  GSP key: Class\\%s (fw=%d)\n", sub, fw)
		fmt.Printf("  AdapterString: %s\n", adapter)
	} else {
		fmt.Println("  [!] " + adapter) // when no match, hxcore.GspDiag returns the diagnostic string
	}
	// v2.6.x: Gen2 driver deploy status (does not depend on whether the driver is currently running -
	// after S0 remove-when-done the System32 file being missing is the normal end state;
	// the criterion is backup source / service / Defender; see hxcore/drvstate.go)
	dep := hxcore.InspectGen2Drivers()
	if !hxcore.Gen2DriversDeployedOnce() {
		fmt.Println("Gen2 driver: never deployed - run the installer (page 2, tick the driver) then reboot for it to take effect")
	} else {
		for _, d := range dep {
			svcS := "not registered"
			if d.SvcReg {
				svcS = d.SvcStart
				if d.SvcRunning {
					svcS += "/running"
				}
			}
			fmt.Printf("Gen2 driver %-16s backup source=%v  System32=%s  service=%s\n",
				d.File, map[bool]string{true: "OK", false: "missing"}[d.BackupOK], d.SysState.String(), svcS)
		}
	}
	if ex, err := hxcore.DefenderExclusionsPresent(); err != nil {
		fmt.Println("Defender exclusion: query failed (" + err.Error() + ")")
	} else if ex {
		fmt.Println("Defender exclusion: whitelisted (OK)")
	} else {
		fmt.Println("Defender exclusion: missing - antivirus may delete the driver; re-run the installer to re-add")
	}
	// driver and unlock live test: primary criterion = device actually openable (does not depend on sc.exe - some hardened environments disable it)
	// v2.5: TS (ThrottleStop) + WinRing0 BYOVD; no longer need 50hx_bridge
	st := hxcore.ReadUnlockStateV2(5, 800)
	tsRun := st.TSOK
	winringRun := st.WinRingOK
	fmt.Printf("ThrottleStop: %v\n", tsRun)
	fmt.Printf("WinRing0: %v\n", winringRun)
	if tsRun && winringRun {
		fmt.Printf("PCIe link: Gen%d\n", st.Speed)
		if st.SS0OK {
			fmt.Printf("SS0 (compute): 0x%08x %s\n", st.SS0, map[bool]string{true: "(unlocked)", false: "(locked)"}[st.Unlocked])
		}
	} else {
		fmt.Println("Driver not running (once installed, Gen2 / status can be used)")
	}
	ss0 := st.SS0
	ss0ok := st.SS0OK
	speed := st.Speed
	// v2.4: popup includes diagnostics and recommended actions (community users don't need to depend on the log)
	diag := []string{}
	if !gpuOK {
		diag = append(diag, "- 50HX not detected - please confirm the GPU is seated and the driver is installed")
	}
	if sb {
		diag = append(diag, "- Secure Boot is on: enter the BIOS to disable it, otherwise the unlock EFI is rejected")
	}
	if ts {
		diag = append(diag, "- Test signing is on - v2.5 does not need it; run 'bcdedit /set testsigning off' to disable")
	}
	if !gs {
		diag = append(diag, "- GSP is not enabled: may black screen after unlock. Run the installer (it will automatically set EnableGpuFirmware=1)")
	}
	if !tsRun || !winringRun {
		diag = append(diag, "- Drivers are not running: they will be auto-started at the next logon; or run '50HXInstaller.exe -gen2' manually")
	}
	if tsRun && winringRun {
		if !ss0ok {
			diag = append(diag, "- Drivers running but the compute register cannot be read (abnormal)")
		} else if ss0 == 0x88888888 {
			diag = append(diag, fmt.Sprintf("- SS0=0x%08x: compute unlocked! PCIe Gen%d", ss0, speed))
		} else {
			diag = append(diag, fmt.Sprintf("- SS0=0x%08x: compute still locked - the 50HX Unlock EFI did not run successfully at reboot", ss0))
			// v2.4.4: read the EFI unlock log (50hx_log.txt) for automatic diagnostics; no need to read the log manually
			efiDiag := hxcore.AnalyzeEfiLog()
			if efiDiag != "" {
				diag = append(diag, efiDiag)
			}
		}
	}
	msg := "50HX unlock status\n========================\n"
	msg += fmt.Sprintf("GPU 40HX: %v    Secure Boot: %v\n", map[bool]string{true: "OK", false: "MISSING"}[gpuOK], map[bool]string{true: "ON!", false: "disabled (OK)"}[sb])
	msg += fmt.Sprintf("Test signing: %v    GSP: %v\n", map[bool]string{true: "ON", false: "OFF"}[ts], map[bool]string{true: "ON", false: "OFF"}[gs])
	msg += fmt.Sprintf("ThrottleStop: %v  WinRing0: %v\n", map[bool]string{true: "running", false: "stopped"}[tsRun], map[bool]string{true: "running", false: "stopped"}[winringRun])
	if tsRun && winringRun {
		msg += fmt.Sprintf("PCIe: Gen%d    SS0: 0x%08x\n", speed, ss0)
	}
	msg += "\nDiagnostics:\n" + strings.Join(diag, "\n")
	if len(diag) == 0 {
		msg += "- everything is normal"
	}
	msg += "\n\nDetailed log: " + filepath.Join(os.TempDir(), "50HX_installer.log")
	msgbox("50HX status", msg, mbIconInfo)
	fmt.Println("=== status finished ===")
}

func pause() {
	// GUI build: no need to press Enter; output goes to the log, interactive wrap-up uses the message box
}
