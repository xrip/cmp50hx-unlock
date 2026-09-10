// 40HXCheck — CMP 50HX unlock standalone diagnostic tool v3.0.0
//
// Double-click to diagnose; read-only by default. Since v2.5, when it
// detects "compute / Gen2 cannot be measured live (driver not running)"
// and the driver files are present in the package, it temporarily loads
// ThrottleStop + WinRing0 to take the measurement, then self-cleans
// (remove-when-done, leaves no trace):
//
//	① Highest-priority display: compute-unlock status + PCIe Gen2 status
//	② Next: GPU / Secure Boot / GSP / test signing
//	③ Details and recommendations
//
// The installer (40HXInstaller) is responsible for "install"; this tool
// is responsible for "check".
//
// Shared implementation with tools/50hxcore (the same probe / diagnostic
// code as the installer — no drift).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	hxcore "50hxcore"
	"golang.org/x/sys/windows"
)

const (
	appTitle     = "CMP 50HX Unlock Diagnostics"
	logsDirName  = "50HXUnlock"              // %LOCALAPPDATA%\50HXUnlock\logs
	gen2TaskName = "50HX PCIe Gen2 Bring-up" // Same name as the installer's setupGen2Task
)

var (
	procMsgBoxW = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
)

// ---- v2.5: temporary driver management (ThrottleStop + WinRing0, remove-when-done) ----
const (
	fileTS = "ThrottleStop.sys"
	fileWR = "WinRing0x64.sys"
	svcTS  = "ThrottleStop"
	svcWR  = "WinRing0_1_2_0"
)

func sysDrvDir() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "drivers")
}

// driverSrcDir locates drivers/ inside the package layout (v2.5:
// gen2/drivers next to the exe / ProgramData backup).
func driverSrcDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	pd := filepath.Join(os.Getenv("ProgramData"), "50HXUnlock", "drivers") // backup source left by the installer
	for _, c := range []string{
		pd,
		filepath.Join(dir, "gen2", "drivers"),
		filepath.Join(dir, "drivers"),
	} {
		if _, e1 := os.Stat(filepath.Join(c, fileTS)); e1 == nil {
			if _, e2 := os.Stat(filepath.Join(c, fileWR)); e2 == nil {
				return c
			}
		}
	}
	return ""
}

func svcState(name string) string {
	_, _, st := hxcore.ServiceInfo(name)
	return st
}

// throttleStopAppRunning reports whether the ThrottleStop application is
// currently running on this host (it shares the driver name; do not
// delete its driver).
func throttleStopAppRunning() bool {
	out, _ := hxcore.RunOut("tasklist.exe", "/fi", "imagename eq ThrottleStop.exe")
	return strings.Contains(out, "ThrottleStop.exe")
}

// ensureDrivers ensures the TS/WinRing0 services are RUNNING. Already
// running → don't touch (externally managed); otherwise deploy and start
// from the package's drivers directory.
// Returns (deployed — whether this tool deployed/attempted to start it,
// ok — whether both are running, fail — clue for the start failure).
// AV quarantine commonly replaces .sys with a 0-byte placeholder (file
// still present) → checking only "missing" misses it, so we self-heal
// missing/0-byte cases by redeploying; after redeploy, add the Defender
// exclusion to prevent re-deletion.
// Note: "starting the driver" is itself a driver-load test — failures
// can mostly be attributed (see classifyLoadErr).
func ensureDrivers() (deployed bool, ok bool, fail string) {
	src := driverSrcDir()
	allRunning := svcState(svcTS) == "RUNNING" && svcState(svcWR) == "RUNNING"
	if allRunning {
		return false, true, ""
	}
	if src == "" {
		return false, false, "No driver directory for temporary load was found in the release package (gen2\\drivers)"
	}
	var fails []string
	for _, d := range []struct{ svc, file string }{
		{svcTS, fileTS}, {svcWR, fileWR},
	} {
		dst := filepath.Join(sysDrvDir(), d.file)
		if b, e := os.ReadFile(dst); e != nil || len(b) == 0 {
			if sb, e2 := os.ReadFile(filepath.Join(src, d.file)); e2 == nil {
				os.WriteFile(dst, sb, 0o644)
				_ = hxcore.AddDefenderExclusions() // best-effort, prevents re-deletion
			}
		}
		if svcState(d.svc) == "RUNNING" {
			continue
		}
		deployed = true
		hxcore.RunOut("sc.exe", "create", d.svc, "type=", "kernel",
			"start=", "demand", "binPath=", `\SystemRoot\System32\drivers\`+d.file)
		if _, err := hxcore.RunOut("sc.exe", "start", d.svc); err != nil {
			// Service may be marked for deletion (1072) / disabled (1058)
			// → clear the flag, recreate, and start again
			// (matches the installer's ensureSvcLoaded; even a residual
			// post-uninstall state self-heals into a loadable driver).
			hxcore.RunOut("sc.exe", "delete", d.svc)
			hxcore.RunOut("sc.exe", "create", d.svc, "type=", "kernel",
				"start=", "demand", "binPath=", `\SystemRoot\System32\drivers\`+d.file)
			if out2, err2 := hxcore.RunOut("sc.exe", "start", d.svc); err2 != nil {
				fails = append(fails, d.file+": "+strings.TrimSpace(out2))
			}
		}
	}
	time.Sleep(400 * time.Millisecond)
	ok = svcState(svcTS) == "RUNNING" && svcState(svcWR) == "RUNNING"
	if !ok && len(fails) > 0 {
		fail = strings.Join(fails, " || ")
	}
	return deployed, ok, fail
}

// classifyLoadErr turns the raw "driver load failed" error into a
// user-understandable cause and remediation.
func classifyLoadErr(raw string) string {
	r := strings.ToLower(raw)
	switch {
	case strings.Contains(r, "1275"):
		return "Windows security settings blocked driver load (error 1275) — most often Defender's 'Core Isolation / Memory Integrity', 'Vulnerable Driver Blocklist', or Smart App Control; please temporarily disable these in Windows Security and retry (you can re-enable after loading)"
	case strings.Contains(r, "577"):
		return "Driver image was rejected by the system (error 577) — the file was altered or a security policy intercepted it; please re-run 40HXInstaller to redeploy the original driver, and check Security Center's 'Untrusted driver' setting"
	case strings.Contains(r, "1058"):
		return "Service is disabled (error 1058) — this tool has tried to switch it back and recreate it"
	case strings.Contains(r, "1072"):
		return "Service is in 'marked for delete' residual state (error 1072) — this tool has recreated and retried"
	case strings.Contains(r, "拒绝访问"), strings.Contains(r, "access is denied"), strings.Contains(r, "error 5"), strings.Contains(r, " 5:"):
		return "Insufficient privileges (error 5) — please run this tool as administrator"
	case strings.Contains(r, "1060"), strings.Contains(r, "不存在"):
		return "Service not found (error 1060) — the driver file was not deployed successfully, re-run the installer and retry"
	}
	return "Driver start failed — usually a third-party AV's HIPS / driver block; please allow both .sys files in its trust/whitelist and retry; if it still fails, send the log to the author"
}

// cleanupDrivers self-cleans: stop the service, delete it, delete the
// driver file (leaves no trace, no on-disk residue for anti-cheat).
// If ThrottleStop is currently using the driver on this host, do NOT
// delete it (avoids interrupting the user's tool).
func cleanupDrivers() {
	if throttleStopAppRunning() {
		return
	}
	// Respect the driver runtime strategy: under "Resident" this tool
	// never uninstalls; the other strategies (remove-when-done / auto-
	// retry on failure) clean up normally.
	switch hxcore.DriverStrategy() {
	case hxcore.DriverStrategyResident:
		fmt.Println("  Resident policy: keeping driver service and files (diagnostic does not clean up)")
		return
	}
	for _, d := range []struct{ svc, file string }{
		{svcTS, fileTS}, {svcWR, fileWR},
	} {
		hxcore.RunOut("sc.exe", "stop", d.svc)
		hxcore.RunOut("sc.exe", "delete", d.svc)
		os.Remove(filepath.Join(sysDrvDir(), d.file))
	}
}

func msgbox(text string, icon uint) {
	t, _ := syscall.UTF16PtrFromString(appTitle)
	b, _ := syscall.UTF16PtrFromString(text)
	procMsgBoxW.Call(0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), uintptr(icon))
}

// isAdmin: same implementation as the installer (TokenElevation may
// falsely report 0 in restricted contexts; try SCM with full rights).
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
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err == nil {
		windows.CloseServiceHandle(scm)
		return true
	}
	return false
}

// selfElevate: when not admin, ShellExecute runas to relaunch with
// elevation (the diagnostic needs to mount the ESP and read 50hx_log).
func selfElevate() {
	exe, _ := os.Executable()
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	args := append([]string{}, os.Args[1:]...)
	args = append(args, "-elevated")
	params, _ := syscall.UTF16PtrFromString(strings.Join(args, " "))
	proc := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")
	r, _, _ := proc.Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)), 0, 1)
	if r <= 32 {
		msgbox("Administrator privileges are required to read the EFI unlock log (50hx_log.txt).\nPlease right-click this program -> Run as administrator.", 0x30)
	}
	os.Exit(0)
}

// logsDir returns %LOCALAPPDATA%\50HXUnlock\logs (unified log-collecting
// directory — easy for the user to find).
func logsDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	d := filepath.Join(base, logsDirName, "logs")
	os.MkdirAll(d, 0o755)
	return d
}

// collectLogs gathers the related logs into a fixed directory and returns
// the directory path.
func collectLogs(diagSnapshot string) string {
	dir := logsDir()
	// 1. Installer / Gen2 log (%TEMP%\50HX_installer.log).
	if b, err := os.ReadFile(filepath.Join(os.TempDir(), "50HX_installer.log")); err == nil {
		os.WriteFile(filepath.Join(dir, "installer.log"), b, 0o644)
	}
	// 2. EFI unlock-chain log (50hx_log.txt at the ESP root) — readable
	//    as admin; v3.0.0: only collected if the unlock EFI binary itself
	//    is still present — after uninstalling the EFI, the file is a
	//    historical leftover, and copying it into logs would be
	//    mistaken for the current EFI run log during triage.
	if esp := hxcore.MountESP(); esp != "" {
		if _, efiErr := os.Stat(esp + `:\EFI\50HX\50HXUNLK.EFI`); efiErr == nil {
			if b, err := os.ReadFile(esp + ":\\50hx_log.txt"); err == nil {
				os.WriteFile(filepath.Join(dir, "50hx_log.txt"), b, 0o644)
			}
		}
		hxcore.UnmountESP(esp)
	}
	// 3. Current diagnostic snapshot (latest) + timestamped archive
	//    (kept for history / comparison).
	os.WriteFile(filepath.Join(dir, "diagnose.txt"), []byte(diagSnapshot), 0o644)
	ts := time.Now().Format("20060102_150405")
	os.WriteFile(filepath.Join(dir, "diagnose_"+ts+".txt"), []byte(diagSnapshot), 0o644)
	return dir
}

// indentLines applies a uniform 4-space indent to every line of a
// multi-line string (for displaying status-file contents).
func indentLines(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, ln := range lines {
		lines[i] = "    " + ln
	}
	return strings.Join(lines, "\n")
}

// copyToClipboard calls PowerShell Set-Clipboard (silent failure —
// enhancement only, never blocking).
func copyToClipboard(s string) bool {
	f, err := os.CreateTemp("", "50hx_clip_*.txt")
	if err != nil {
		return false
	}
	p := f.Name()
	f.WriteString(s)
	f.Close()
	defer os.Remove(p)
	out, err := hxcore.RunOut("powershell.exe", "-NoProfile", "-Command",
		"Get-Content -LiteralPath '"+p+"' -Raw -Encoding UTF8 | Set-Clipboard")
	return err == nil && !strings.Contains(out, "denied")
}

// ---- v2.6.0: enhanced diagnostic snapshot to help community feedback triage ----
// Four rich-text sections — environment / drivers / raw PCIe registers /
// known limits — written to diagnose.txt and the clipboard.

// osVersion: Windows version / build number (cmd /c ver).
func osVersion() string {
	out, _ := hxcore.RunOut("cmd.exe", "/c", "ver")
	out = strings.TrimSpace(out)
	if out == "" {
		out = "Unknown"
	}
	arch := os.Getenv("PROCESSOR_ARCHITECTURE")
	if arch == "" {
		arch = "?"
	}
	return fmt.Sprintf("%s [%s]", out, arch)
}

// driverDetail: detailed deployment status of one driver — data source
// is hxcore.InspectGen2Drivers(), the same status evaluation as the
// installer GUI page ① and -status (backup source / four System32 states
// / service registration & start type / runtime state), so the
// diagnostic and the installer always say the same thing about the same
// machine.
func driverDetail(svc, file string) string {
	for _, d := range hxcore.InspectGen2Drivers() {
		if d.Service != svc || d.File != file {
			continue
		}
		sysS := "System32 missing"
		switch d.SysState {
		case hxcore.DrvZero:
			sysS = "System32 0 bytes ⚠ AV quarantine placeholder"
		case hxcore.DrvSizeMismatch:
			sysS = fmt.Sprintf("System32 size=%d bytes ⚠ disagrees with backup (replaced?)", d.SysSize)
		case hxcore.DrvOk:
			sysS = fmt.Sprintf("System32 size=%d bytes", d.SysSize)
		}
		svcS := "Service not registered"
		if d.SvcReg {
			svcS = "Service " + d.SvcStart
			if d.SvcStart == "DISABLED" {
				svcS += " ⚠ disabled (Gen2 cannot start, re-run the installer to repair)"
			} else if d.SvcRunning {
				svcS += "/running"
			} else {
				svcS += " (demand, waiting for logon task to start it)"
			}
		}
		backS := "No backup source (never installed)"
		if d.BackupOK {
			backS = "Backup source OK (previously deployed)"
			if d.SysState == hxcore.DrvAbsent && !d.SvcReg {
				backS += "; remove-when-done self-cleanup is normal, logon task will auto-redeploy"
			}
		}
		return fmt.Sprintf("  %-16s %s | %s | %s\n", d.File, sysS, svcS, backS)
	}
	return fmt.Sprintf("  %-16s (status check not covered)\n", file)
}

// spdName: PCIe link-speed encoding → human name.
func spdName(s uint32) string {
	names := []string{"?", "Gen1(2.5GT/s)", "Gen2(5GT/s)", "Gen3(8GT/s)", "Gen4(16GT/s)", "Gen5"}
	if s >= uint32(len(names)) {
		return "?"
	}
	return names[s]
}

// rawPcieDump: raw PCIe link registers + BAR0 BOOT_0 (the core evidence
// for diagnosing Gen2).
func rawPcieDump() string {
	wh, err := hxcore.OpenDevice(`\\.\WinRing0_1_2_0`)
	if err != nil {
		return "  (WinRing0 unavailable, skipping raw register read)\n"
	}
	defer hxcore.CloseHandle(wh)
	bdf, ok := hxcore.FindGPUPCI(wh)
	if !ok {
		return "  (FindGPUPCI did not locate 40HX, skipping)\n"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  BDF=0x%05X (bus=%d dev=%d fn=%d)\n", bdf,
		(bdf>>8)&0xFF, (bdf>>3)&0x1F, bdf&0x7))
	cap := hxcore.PcieCap(wh, bdf)
	if cap == 0 {
		return sb.String() + "  (no PCIe Capability)\n"
	}
	rd := func(off uint32) uint32 {
		v, e := hxcore.PciRd(wh, bdf, off)
		if e != nil {
			return 0xFFFFFFFF
		}
		return v
	}
	lnkcap, lnkctl, lnksta := rd(cap+0x0C), rd(cap+0x10), rd(cap+0x12)
	lnkctl2, lnksta2 := rd(cap+0x30), rd(cap+0x32)
	sb.WriteString(fmt.Sprintf("  LNKCAP =0x%08X  MaxLinkSpeed=%s\n", lnkcap, spdName(lnkcap&0xF)))
	sb.WriteString(fmt.Sprintf("  LNKCTL =0x%08X (ASPM=%d RetrainLink=%d)\n", lnkctl, (lnkctl>>0)&3, (lnkctl>>5)&1))
	sb.WriteString(fmt.Sprintf("  LNKSTA =0x%08X current=%s width=x%d\n", lnksta, spdName(lnksta&0xF), (lnksta>>4)&0x3F))
	sb.WriteString(fmt.Sprintf("  LNKCTL2=0x%08X target=%s\n", lnkctl2, spdName(lnkctl2&0xF)))
	sb.WriteString(fmt.Sprintf("  LNKSTA2=0x%08X\n", lnksta2))
	// BAR0 BOOT_0 — confirms BAR0 really points at 50HX MMIO.
	if bar0raw, e := hxcore.PciRd(wh, bdf, 0x10); e == nil {
		bar0 := uint64(bar0raw & 0xFFFFFFF0)
		th, e2 := hxcore.OpenThrottleStop()
		if e2 == nil {
			defer hxcore.CloseHandle(th)
			if v, e3 := hxcore.TSRead(th, bar0+0x0); e3 == nil {
				fam := (v >> 24) & 0xFF
				tag := "Unknown"
				if fam == 0x16 {
					tag = "TU10x (50HX OK)"
				}
				sb.WriteString(fmt.Sprintf("  BAR0+0x00 BOOT_0=0x%08X (family=0x%02X %s)\n", v, fam, tag))
			} else {
				sb.WriteString(fmt.Sprintf("  BAR0+0x00 BOOT_0 read failed: %v\n", e3))
			}
		} else {
			sb.WriteString("  (ThrottleStop unavailable, skipping BOOT_0)\n")
		}
	}
	return sb.String()
}

// knownIssuesBlock: known limits / potential issues — for cross-checking
// during community feedback.
func knownIssuesBlock() string {
	var sb strings.Builder
	sb.WriteString("\n--- Known limits / potential issues (v3.0.0, items the community has not fully covered) ---\n")
	sb.WriteString("· Driver / GSP holds the link policy (GSP-RM): at idle / low load nvlddmkm writes the GPU-side TLS back to Gen1; Stage2 automatic fallback or LD (-hard) clears it. **Not** confirmed as firmware write-protection (batch numbers .06/.04 are not a valid criterion), **do NOT flash VBIOS** — if it still fails, send the diagnostic and the log to the author.\n")
	sb.WriteString("· Cheap boards / multi-GPU: retrain-only cannot train up to Gen2 on some motherboards / topologies; requires a Root Link Disable fallback (instant link drop). Since v2.6 the logon task automatically tries Stage2 once (Gen2AutoHard); if it still fails you can run `50HXInstaller.exe -gen2 -hard` manually.\n")
	sb.WriteString("· EFI cannot find the card (legacy only scanned bus 0-7): v3.0 extended to 0-16 + a CF8 full 0-255 fallback, covering AGESA / high-bus cases (MSI B450 measured at bus 0x10); if reinstalling the v3.0 EFI still reports not found, the firmware likely did not initialise that headless slot — go to BIOS: Above4G + Re-Size BAR / Init Display First=PEG / plug into the CPU top slot, and send 50hx_log.txt (including the \"diag: CF8 visible devices\" device-mapping section) to the author.\n")
	sb.WriteString("· Idle power-saving downshift: under low load the link drops to Gen1 which is normal — load brings it back to Gen2 automatically; if the diagnostic shows TLS=Gen2, the configuration succeeded — not a failure.\n")
	sb.WriteString("· Coexistence with ThrottleStop software: this tool's driver shares the name with ThrottleStop, automatically reusing its driver — never deletes or interrupts it; on conflict close ThrottleStop and re-run.\n")
	sb.WriteString("· AV quarantine: third-party AVs may quarantine driver .sys files; Defender exclusions are added; for other AV products, allow this project's files in their security center.\n")
	sb.WriteString("· Driver signing: renaming and recompiling a .sys loses the original signature and requires a test signature / EV cert; official release files keep the original signature.\n")
	sb.WriteString("· When filing an issue, please attach: this diagnostic txt + %TEMP%\\50HX_installer.log + motherboard / CPU / GPU / OS version.\n")
	return sb.String()
}

// drvLogEvidence: when the driver cannot be loaded (drvOK=false), reads
// back the historical logs to decide "has the driver ever run successfully?",
// returning (everRan, summary). Used to give targeted advice instead of
// the generic "driver not ready" — community feedback can then
// distinguish "unlock already in effect but we lack permission to
// confirm this session" vs "never deployed, needs reinstall".
func drvLogEvidence() (bool, string) {
	var parts []string
	// 1. gen2_status.txt (scheduled-task historical snapshot).
	if gs := hxcore.ReadGen2Status(); gs != "" {
		for _, ln := range strings.Split(gs, "\n") {
			t := strings.TrimSpace(ln)
			if strings.Contains(t, "Gen2") || strings.Contains(t, "无需操作") || strings.Contains(t, "ACHIEVED") {
				parts = append(parts, "Scheduled-task history: "+t)
				break
			}
		}
	}
	// 2. installer.log (install / task run log) — contains hard
	// evidence of driver load and Gen2 achievement.
	logPath := filepath.Join(os.TempDir(), "50HX_installer.log")
	if b, err := os.ReadFile(logPath); err == nil {
		s := string(b)
		if strings.Contains(s, "GEN2 ACHIEVED") || strings.Contains(s, "BAR0 校验通过") {
			parts = append(parts, "installer.log: driver loaded successfully and achieved Gen2")
		}
		if strings.Contains(s, "启动服务") && strings.Contains(s, "失败") {
			parts = append(parts, "installer.log: a driver-start failure was previously seen (possibly AV quarantine / 1072 residual)")
		}
	}
	if len(parts) == 0 {
		return false, ""
	}
	return true, strings.Join(parts, "; ")
}

func check() {
	var sb strings.Builder
	w := func(format string, a ...interface{}) { sb.WriteString(fmt.Sprintf(format, a...)) }
	var tips []string
	// v2.6.0: write the version banner into sb so it is visible in both
	// the popup and diagnose.txt (previously fmt.Println only went to the log).
	w("==============================================\n")
	w("  CMP 50HX Unlock Diagnostics  v3.0.0   %s\n", time.Now().Format("2006-01-02 15:04:05"))
	w("==============================================\n")
	gpuOK := hxcore.FindGPU()
	sbOn := hxcore.SecureBootOn()
	tsOn := hxcore.TestSigningOn()
	gsOn := hxcore.GspEnabled()
	sub, _, _ := hxcore.GspDiag() // Only need to know if the GSP key exists (toggle-style display; no register/Adapter details).

	// --- A. Main verdict: compute + Gen2 highest priority (v2.5) ---
	selfM, drvOK, drvFail := ensureDrivers()
	st := hxcore.ReadUnlockStateV2(6, 800)
	bar := strings.Repeat("=", 46)
	w("\n%s\n", bar)
	state := "Cannot measure live (driver not ready)"
	switch {
	case st.SS0OK && st.Unlocked && st.Speed >= 2:
		state = "Compute unlocked + Gen2 achieved"
	case st.SS0OK && st.Unlocked && st.TLS >= 2:
		state = "Compute unlocked + Gen2 target configured (current link not at Gen2)"
	case st.SS0OK && st.Unlocked:
		state = "Compute unlocked, Gen2 not achieved"
	case st.SS0OK:
		state = "Not unlocked (SS0 locked)"
	}
	w("  Unlock status: %s\n", state)
	comp := "Unreadable"
	if st.SS0OK {
		comp = fmt.Sprintf("%s (SS0=0x%08X SS1=0x%08X)",
			map[bool]string{true: "✓ Full unlock", false: "✗ Locked"}[st.Unlocked], st.SS0, st.SS1)
	}
	spd := "Unreadable"
	if st.Speed >= 1 {
		names := map[uint32]string{1: "Gen1 (2.5 GT/s)", 2: "Gen2 (5.0 GT/s)", 3: "Gen3 (8.0 GT/s)", 4: "Gen4 (16 GT/s)"}
		spd = names[st.Speed]
		if spd == "" {
			spd = fmt.Sprintf("Gen%d", st.Speed)
		}
		if st.Width >= 1 {
			spd += fmt.Sprintf(" x%d", st.Width)
		}
		if st.Speed < 2 && st.TLS >= 2 {
			spd += fmt.Sprintf(" (target Gen%d — idle power-saving downshift is normal; if it stays Gen1 under sustained load, see the verdict)", st.TLS)
		}
	}
	w("  Compute : %s\n", comp)
	w("  PCIe    : %s\n", spd)
	w("%s\n", bar)

	// --- B. Basic status ---
	gspTxt := "✗ Not enabled (set automatically by the installer after the NVIDIA driver is installed)"
	if gsOn {
		gspTxt = "✓ Enabled"
	} else if sub == "" {
		gspTxt = "— GSP key not found (install the NVIDIA driver first, then the installer can set GSP)"
	}
	w("GPU 40HX: %s   Secure Boot: %s   GSP: %s\n",
		map[bool]string{true: "✓", false: "✗"}[gpuOK],
		map[bool]string{true: "On (must be disabled!)", false: "Off (OK)"}[sbOn], gspTxt)
	w("Test signing: %s  (not required since v2.5, recommend off)\n",
		map[bool]string{true: "Enabled", false: "Disabled"}[tsOn])
	// v2.6.0: boot mode + power settings — Legacy/MBR, Fast Startup, and
	// ASPM are three high-frequency root causes (corresponding to "EFI
	// won't install", "shutdown-then-boot skips EFI", and "idle Gen1
	// false-positive failure").
	bootMode := "UEFI (OK)"
	if hxcore.FirmwareIsLegacy() {
		bootMode = "Legacy BIOS+MBR (no EFI partition, compute unlock unavailable!)"
	}
	fsOn := hxcore.FastStartupOn()
	ac, dc, aspmOK := hxcore.ASPMSavings()
	aspmStr := "Undetectable (skipped)"
	if aspmOK {
		if ac == 0 && dc == 0 {
			aspmStr = "Off (OK)"
		} else {
			aspmStr = fmt.Sprintf("On (AC=%d DC=%d) — may downshift to Gen1 at idle, recommend disabling", ac, dc)
		}
	}
	w("Boot mode: %s\n", bootMode)
	w("Fast Startup: %s   PCIe ASPM: %s\n",
		map[bool]string{true: "On (recommend off)", false: "Off (OK)"}[fsOn],
		aspmStr)

	// --- C. Details: Gen2 drivers (per-driver) / task / historical records ---
	// Display each driver individually: one may be blocked by AV while the
	// other is fine, so a summary only would mislead.
	tsTxt := "✗ Not running"
	if st.TSOK {
		tsTxt = "✓ Available"
	} else if svcState(svcTS) == "RUNNING" {
		tsTxt = "⚠ Service present, but device cannot be opened"
	}
	wrTxt := "✗ Not running"
	if st.WinRingOK {
		wrTxt = "✓ Available"
	} else if svcState(svcWR) == "RUNNING" {
		wrTxt = "⚠ Service present, but device cannot be opened"
	}
	w("Gen2 drivers: ThrottleStop %s   WinRing0 %s\n", tsTxt, wrTxt)
	if selfM {
		w("  ↑ This diagnostic temporarily loaded them to take the reading and will unload on exit — does NOT mean installed\n")
	} else if st.TSOK || st.WinRingOK {
		w("  ↑ Drivers are already deployed / externally loaded\n")
	}
	if !drvOK && drvFail != "" {
		w("  └ Start failed: %s\n", classifyLoadErr(drvFail))
	}
	w("\n")
	taskOK, taskStatus, taskResult := hxcore.TaskInfo(gen2TaskName)
	w("Gen2 task: %s\n",
		map[bool]string{true: "Registered (" + taskStatus + ", last result: " + taskResult + ")",
			false: "Not registered (fix: right-click and run 50HXInstaller.exe -task as administrator)"}[taskOK])
	// gen2_status.txt is the "historical snapshot" written by the last
	// Gen2 task run, NOT a live reading for this session: only show it as
	// reference when the live driver measurement isn't available, and
	// clearly label it as a historical record to avoid the misleading
	// "✅ Gen2" after uninstall.
	if !st.SS0OK || st.Speed < 2 {
		if gs := hxcore.ReadGen2Status(); gs != "" {
			w("  Note: a historical record from the last Gen2 task is present (not a live reading):\n%s\n", indentLines(gs))
			if !drvOK {
				w("       ↑ Driver is currently not running — this is historical residue, not the current state\n")
			}
		}
	}
	if drvOK && !st.SS0OK {
		w("(Driver is running but compute register cannot be read — abnormal)\n")
	}

	// --- D. Verdict and recommendations ---
	verdict := ""
	switch {
	case st.Unlocked && st.Speed >= 2:
		verdict = ">>> Unlock succeeded: Tensor full unlock + Gen2"
		if st.Width >= 1 {
			verdict += fmt.Sprintf(" x%d", st.Width)
		} else {
			verdict += " (link width not measured)"
		}
	case st.Unlocked && st.TLS >= 2:
		if st.Speed == 1 {
			verdict = ">>> Compute unlocked + Gen2 target configured (currently Gen1: idle power-saving downshift or not trained yet this session; comes back under load / after retrain)"
		} else {
			verdict = ">>> Compute unlocked + Gen2 target configured (current link speed not measured)"
		}
	case st.Unlocked:
		verdict = ">>> Compute unlocked; Gen2 not achieved — the logon task already runs on every login (including automatic Stage2); if it still fails, try the [Run Gen2 now] button in GUI area ② (see README §5.2)"
	case st.SS0OK:
		verdict = ">>> Not unlocked this boot (SS0 locked)"
		default:
			if !drvOK {
				if !isAdmin() {
					verdict = ">>> Driver not loaded: this tool needs administrator rights to load the kernel driver for live measurement. Please right-click this program -> Run as administrator"
				} else if gpuOK && gsOn {
					if ever, ev := drvLogEvidence(); ever {
						verdict = ">>> Driver is currently not running, but logs show Gen2 was previously achieved (" + ev + "). The unlock is already in effect; right-click and run as administrator to read the live state"
					} else {
						verdict = ">>> Driver unavailable — please run from the 50HXUnlock release directory (contains gen2\\drivers), or first re-run 50HXInstaller.exe as administrator to install the driver"
					}
				} else {
					verdict = ">>> Cannot complete the unlock verdict (see the items above)"
				}
			} else {
				verdict = ">>> Cannot complete the unlock verdict (see the items above)"
			}
		}
	w("\n%s\n", verdict)
	if st.SS0OK && !st.Unlocked {
		if reason := hxcore.AnalyzeEfiLog(); reason != "" {
			w("%s\n", reason)
		}
	}

	// v2.6.0: the popup only shows the "concise verdict + basic status";
	// detailed recommendations / raw registers only go into diagnose.txt
	// (the log) and the clipboard — not into the GUI. Per the user's
	// request, hints go in the txt, not the popup; the community can
	// look at the logs directory for the full diagnostic.
	guiHead := sb.String()

	if !gpuOK {
		tips = append(tips, "· 40HX not detected: confirm the card is seated and the driver is installed")
	}
	if sbOn {
		tips = append(tips, "· Secure Boot is ON: disable it in the BIOS (otherwise the unlock EFI will be rejected)")
	}
	if tsOn {
		tips = append(tips, "· Test signing is ON (not required since v2.5): run `bcdedit /set testsigning off` to disable it")
	}
	if !gsOn {
		tips = append(tips, "· GSP is not enabled: double-click 50HXInstaller.exe -> in ① tick [GSP enable] and click [Install selected components]")
	}
	if gpuOK && st.SS0OK && !st.Unlocked {
		tips = append(tips, "· EFI compute unlock is not in effect (SS0 locked): if the unlock EFI '50HX Unlock' is not deployed / has been uninstalled on this machine, this warning is expected and compute stays locked — to restore it, re-run 50HXInstaller.exe and tick [Compute EFI Deploy + firmware boot entry]; if the EFI is already installed, confirm the boot went through the '50HX Unlock' boot entry / Above 4G is enabled / Secure Boot is off")
	}
	// v2.6.0: four targeted hints for the community's high-frequency root causes
	if hxcore.FirmwareIsLegacy() {
		tips = append(tips, "· Boot mode is Legacy BIOS+MBR: there is no EFI partition, compute unlock cannot be installed —\n  follow README §2.4 and use mbr2gpt to convert to GPT, then re-run the installer (Gen2 is unaffected)")
	}
	if fsOn {
		tips = append(tips, "· Fast Startup (hybrid hibernate) is ON: shutdown then power-on may skip a full UEFI boot -> EFI does not run;\n  the installer disables it automatically; manual: Control Panel Power Options, uncheck 'Turn on fast startup'")
	}
	if aspmOK && (ac > 0 || dc > 0) {
		tips = append(tips, "· PCIe link power saving (ASPM) is ON: dropping to Gen1 at idle is normal and load brings it back automatically;\n  to keep Gen2 persistently, disable: powercfg -setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0\n  (also -setdcvalueindex with the same value, then -setactive SCHEME_CURRENT to apply)")
	}
	if !taskOK {
		tips = append(tips, "· Gen2 scheduled task is not registered: Gen2 will not auto-unlock after login —\n  double-click 50HXInstaller.exe -> in ② click [Run Gen2 and install auto-start] for a one-shot (this-session unlock + register auto-start); or in ① tick [Gen2 logon auto-start] and click [Install selected components]")
	}
	if st.SS0OK && st.TLS < 2 && st.TLS >= 1 && st.Unlocked {
		tips = append(tips, "· Gen2 target speed (TLS) is still Gen1: the unlock write did not take effect — if the log shows the four PL0 registers all OK but the read-back LNKCTL2 is still Gen1,\n  it is most often the driver holding the link policy and rewriting within milliseconds; the logon task (if registered) auto-tries on login and runs a Stage2 fallback; if it still fails, first click [Run Gen2 now] in GUI ② (default auto-includes Stage2 fallback) to retry — only use the command-line `50HXInstaller.exe -gen2 -hard` when you have disabled auto-fallback in ② or want to force it. Confirmed NOT to be firmware write-protection, **do NOT flash VBIOS** — if it still fails send the diagnostic and installer.log to the author (see README §5.2)")
	}
	if st.SS0OK && st.Unlocked && st.Speed < 2 && st.TLS >= 2 {
		tips = append(tips, "· Gen2 target is configured (TLS=Gen2) but the current link is Gen1: usually idle power-saving downshift (normal, load brings it back); if it stays Gen1 under sustained load: directly click [Run Gen2 now] in GUI ② to retrain (Gen2AutoHard is on by default, so Stage2 fallback is used automatically); only when ② has auto-fallback off or you want to force it, use the command-line `50HXInstaller.exe -gen2 -hard` (instant link drop, see README §3.3)")
	}
	if !taskOK && st.SS0OK && st.Unlocked && (st.Speed >= 2 || st.TLS >= 2) {
		tips = append(tips, "· Note: the current Gen2 status comes from a live read of the GPU's TLS register; if no unlock procedure has run yet this boot (the auto-start task is not registered), the value is most likely residue from the previous run — a full shutdown / power-on or GPU reset will lock it again. Please use [Run Gen2 and install auto-start] in GUI ② for a one-shot (this-session unlock + register boot-time auto-start)")
	}
	if throttleStopAppRunning() && !drvOK {
		tips = append(tips, "· Detected the ThrottleStop application is running and this tool's driver is not ready: the tool automatically reuses its driver; if it still fails, close ThrottleStop and re-run the installer")
	}
	if !drvOK {
		if drvFail != "" {
			tips = append(tips, "· Gen2 driver could not be loaded: "+classifyLoadErr(drvFail))
		}
		if ever, ev := drvLogEvidence(); ever {
			tips = append(tips, "· Driver is currently not running, but logs show Gen2 was previously achieved ("+ev+") — the unlock is already in effect; right-click and run as administrator to read the live state")
		} else {
			tips = append(tips, "· Driver has never been successfully deployed (no success record in installer.log / gen2_status): double-click 50HXInstaller.exe -> in ① click [One-click full install] to finish deployment and auto-start registration")
		}
	}
	if len(tips) > 0 {
		w("\nRecommendations:\n%s\n", strings.Join(tips, "\n"))
	}
	// The popup only carries the first "next step" (the rest is in
	// diagnose.txt / clipboard) — so the installer can see what to do
	// at a glance.
	popupTip := ""
	if len(tips) > 0 {
		popupTip = "\n\n▶ Next step: " + strings.SplitN(tips[0], "\n", 2)[0]
	}

	// v2.6.0: enhanced diagnostic snapshot — environment / drivers / raw
	// PCIe registers / known limits — to help community feedback triage.
	w("\n========== Environment ==========\n")
	w("  OS      : %s\n", osVersion())
	w("  Admin   : %s   Tool version: v3.0.0\n", map[bool]string{true: "Yes", false: "No"}[isAdmin()])
	w("\n========== Drivers ==========\n")
	w("%s", driverDetail(svcTS, fileTS))
	w("%s", driverDetail(svcWR, fileWR))
	if selfM {
		w("  ↑ This diagnostic [temporarily loaded] the drivers to read hardware state, auto-cleaned on exit — does NOT mean installed\n")
	} else if st.TSOK || st.WinRingOK {
		w("  ↑ Drivers are already deployed / externally loaded, this tool does not clean them\n")
	}
	w("  ThrottleStop app running: %s\n", map[bool]string{true: "Yes (coexists, will not delete its driver)", false: "No"}[throttleStopAppRunning()])
	w("\n========== Raw PCIe registers (40HX) ==========\n")
	w("%s", rawPcieDump())
	w("%s", knownIssuesBlock())

	out := sb.String()
	fmt.Println(out)

	// v2.5: if this tool loaded the drivers, remove-when-done (keeps
	// the system free of third-party drivers).
	if selfM {
		cleanupDrivers()
	}

	dir := collectLogs(out)
	copied := copyToClipboard(out)
	note := ""
	if copied {
		note = "\n\nThe full diagnostic (with troubleshooting recommendations and raw registers) has been copied to the clipboard — paste it straight into the issue."
	}
	ok := st.Unlocked && (st.Speed >= 2 || st.TLS >= 2)
	// The popup only shows the concise verdict + a pointer to the
	// detailed log; the full content is already in diagnose.txt and the
	// clipboard.
	msgbox(guiHead+popupTip+"\n\nThe full diagnostic (with troubleshooting recommendations and raw PCIe registers) has been written to:\n"+dir+"\\diagnose.txt\nSee the AI-assisted install hint.txt in the package for troubleshooting guidance"+note,
		map[bool]uint{true: 0x40, false: 0x30}[ok])
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "-elevated" {
		if !isAdmin() {
			selfElevate()
			return
		}
	}
	// Mirror output to the unified logs directory.
	dir := logsDir()
	if f, err := os.Create(filepath.Join(dir, "40HXCheck.log")); err == nil {
		os.Stdout = f
		os.Stderr = f
		fmt.Fprintf(f, "==== 40HXCheck %s ====\n", time.Now().Format("2006-01-02 15:04:05"))
	}
	check()
}
