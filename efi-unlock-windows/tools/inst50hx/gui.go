package main

// v2.6.0: simplified single-window GUI (walk) — no tabs, no status tables; the installer only handles install.
// On open it runs a single read-only scan (without showing details); the results are used for
//   ① the "environment hint" line in the components area (warnings about undetected card / SecureBoot / Legacy etc.)
//   ② auto-pre-check of missing / not-meeting-target components (already installed stays unchecked = no overwrite).
// Layout (top to bottom):
//   ① Components — [Install selected components] / [One-click full install], auto-rescan after install to refresh hints.
//   ② Gen2 Policy — driver runtime strategy + automatic Stage2 fallback + failure-retry count/interval, [Save policy].
//   ③ Operation log — AttachLogSink live output (GUI and CLI share the full implementation).
// Uninstall and detailed diagnostics are NOT in this window: use 50HXUninstaller.exe / -uninstall / 50HXCheck.exe.
// Threading contract: OnClicked (UI thread) only reads widgets → the goroutine executes → UI changes always go through sync().

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"50hxcore"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows/registry"
)

// ---- Environment scan (read-only; results feed tip and pre-check, no detail table) ----

type statusItem struct {
	name string
	ok   bool
	note string
}

func scanStatus() []statusItem {
	items := []statusItem{}
	legacy := hxcore.FirmwareIsLegacy()
	items = append(items, statusItem{"Boot mode", !legacy,
		map[bool]string{true: "UEFI (OK)", false: "Legacy+MBR — compute unlock unavailable, requires mbr2gpt to convert to GPT"}[legacy]})
	sbOn := hxcore.SecureBootOn()
	items = append(items, statusItem{"Secure Boot", !sbOn,
		map[bool]string{true: "On (must be disabled!)", false: "Off (OK)"}[sbOn]})
	gpuOK := hxcore.FindGPU()
	items = append(items, statusItem{"50HX card", gpuOK,
		map[bool]string{true: "Detected (VEN_10DE&DEV_1E09)", false: "Not detected — confirm the card is seated and the driver is installed"}[gpuOK]})
	gspOK := hxcore.GspEnabled()
	items = append(items, statusItem{"GSP (EnableGpuFirmware)", gspOK,
		map[bool]string{true: "Enabled (OK)", false: "Not enabled — Code 43 black screen is possible after unlock"}[gspOK]})

	espEFI := false
	if esp := hxcore.MountESP(); esp != "" {
		if _, err := os.Stat(esp + ":\\EFI\\50HX\\50HXUNLK.EFI"); err == nil {
			espEFI = true
		}
		hxcore.UnmountESP(esp)
	}
	items = append(items, statusItem{"ESP unlock EFI", espEFI,
		map[bool]string{true: "\\EFI\\50HX\\50HXUNLK.EFI deployed", false: "Not deployed (expected on Legacy machines)"}[espEFI]})
	// Boot-entry tri-state (same semantics as the installer's verifyBootEntry): first in order / exists but not first / not created.
	bootOK := false
	bootNote := "Not created"
	if ex, first, ord := verifyBootEntry(); ex {
		if first {
			bootOK = true
			bootNote = "Exists and first in displayorder"
		} else {
			bootNote = "Exists but not first in displayorder (current order: " + ord + ") — needs to be set as first in the BIOS"
		}
	}
	items = append(items, statusItem{"Firmware boot entry", bootOK, bootNote})

	taskOK, taskStatus, taskResult := hxcore.TaskInfo(gen2TaskName)
	taskNote := "Not registered — Gen2 will not run automatically at boot"
	if taskOK {
		taskNote = "Status " + taskStatus + " last result " + taskResult
	}
	items = append(items, statusItem{"Gen2 logon task", taskOK, taskNote})
	rkOK := runKeyPresent()
	items = append(items, statusItem{"Gen2 Run key fallback", rkOK,
		map[bool]string{true: "Written (50HXGen2)", false: "Not written"}[rkOK]})

	// Gen2 driver layered state — see hxcore/drvstate.go for the logic.
	// After S0 "remove-when-done" / S1 "watchdog" succeeds, the System32 file and service are self-cleaned → missing != never installed.
	deps := hxcore.InspectGen2Drivers()
	if !hxcore.Gen2DriversDeployedOnce() {
		items = append(items, statusItem{"Gen2 drivers (never deployed)", false,
			"No backup source / service — tick [Gen2 driver deploy] below to install"})
	} else {
		var notes []string
		curOK := true
		cleanEnd := true
		for _, d := range deps {
			svcS := "Service not registered"
			if d.SvcReg {
				svcS = "Service " + d.SvcStart
				if d.SvcStart == "DISABLED" {
					svcS += " ⚠ disabled (Gen2 cannot start, re-install to repair)"
				}
				if d.SvcRunning {
					svcS += "/running"
				}
			}
			notes = append(notes, d.File+": System32="+d.SysState.String()+", "+svcS)
			if d.SysState != hxcore.DrvOk || !d.SvcReg || d.SvcStart == "DISABLED" {
				curOK = false
			}
			if d.SvcReg || d.SysState != hxcore.DrvAbsent {
				cleanEnd = false
			}
		}
		if cleanEnd && hxcore.DriverStrategy() != hxcore.DriverStrategyResident {
			items = append(items, statusItem{"Gen2 drivers (remove-when-done end state)", true,
				"Previously deployed; self-cleaned per policy — the logon task will auto-redeploy next login (normal)"})
		} else {
			items = append(items, statusItem{"Gen2 driver deployment status", curOK, strings.Join(notes, " | ")})
		}
	}
	if exOK, err := hxcore.DefenderExclusionsPresent(); err != nil {
		items = append(items, statusItem{"Defender exclusions", false,
			"Query failed (" + err.Error() + ") — re-scan as administrator or ignore"})
	} else {
		items = append(items, statusItem{"Defender exclusions", exOK,
			map[bool]string{true: "Both .sys files + the ProgramData backup directory are whitelisted", false: "Not whitelisted — AV may delete drivers (reinstall to add)"}[exOK]})
	}

	fsOn := hxcore.FastStartupOn()
	items = append(items, statusItem{"Fast Startup", !fsOn,
		map[bool]string{true: "On (recommend off — EFI may not run)", false: "Off (OK)"}[fsOn]})
	if ac, dc, aspmOK := hxcore.ASPMSavings(); aspmOK {
		off := ac == 0 && dc == 0
		items = append(items, statusItem{"PCIe ASPM", off,
			map[bool]string{true: "Off (OK)", false: fmt.Sprintf("On (AC=%d DC=%d) — may downshift to Gen1 at idle", ac, dc)}[off]})
	}
	return items
}

func runKeyPresent() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue("50HXGen2")
	return err == nil
}

// ---- Log-panel writer (AttachLogSink target) ----

type guiLog struct {
	mw *walk.MainWindow
	te *walk.TextEdit
}

func (g *guiLog) Write(p []byte) (int, error) {
	s := string(p)
	if g.mw != nil && g.te != nil {
		// The EDIT control requires CRLF for newlines — normalize all line endings to \r\n, otherwise the log will be mashed into one block.
		s = strings.ReplaceAll(s, "\r\n", "\n")
		s = strings.ReplaceAll(s, "\r", "\n")
		s = strings.ReplaceAll(s, "\n", "\r\n")
		g.mw.Synchronize(func() { g.te.AppendText(s) })
	}
	return len(p), nil
}

// ---- GUI state ----

type guiState struct {
	mw       *walk.MainWindow
	log      *guiLog
	teLog    *walk.TextEdit
	tip      *walk.Label
	busyBy   string // Name of the currently mutex-held operation (""=idle). Read/written on UI thread only:
	// begin() is called from OnClicked (UI thread), end() comes back to the UI thread via sync() → no thread races.
	lastScan  []statusItem
	lastGuide string // Last environment-guide printed (only print on change, avoids re-scan spam)
	lastAV      string // Last detected third-party AV (same as above)
	lastDefWarn string // "No Defender module" hint de-dup

	ckGsp, ckDrv, ckEfi, ckTask            *walk.CheckBox
	ckFast, ckAspm, ckPerf, ckDefOff       *walk.CheckBox
	pbInstall, pbFull                      *walk.PushButton

	rbStrategy     [3]*walk.RadioButton
	ckAutoHard     *walk.CheckBox
	neRetryCnt     *walk.NumberEdit
	neRetryMin     *walk.NumberEdit
	pbSave, pbGen2, pbGen2Install *walk.PushButton
}

func (st *guiState) sync(f func()) {
	if st.mw != nil {
		st.mw.Synchronize(f)
	} else {
		f()
	}
}

// begin: synchronously grab the global mutex on the UI thread (OnClicked) — only one long operation runs at a time.
// Whoever wins holds busyBy and synchronously disables the buttons, preventing the "click-spam / fast double-click" race that would otherwise happen if the goroutine grabbed the lock.
func (st *guiState) begin(what string) bool {
	if st.busyBy != "" {
		fmt.Println("[!] Already running " + st.busyBy + " — " + what + " skipped, please wait for it to finish")
		return false
	}
	st.busyBy = what
	return true
}

func (st *guiState) end() {
	st.sync(func() { st.busyBy = "" })
}

// setActionsEnabled: disable action buttons during the initial auto-scan to prevent racing the manual operations on shared I/O.
func (st *guiState) setActionsEnabled(on bool) {
	st.sync(func() {
		for _, b := range []*walk.PushButton{st.pbInstall, st.pbFull, st.pbSave, st.pbGen2} {
			if b != nil {
				b.SetEnabled(on)
			}
		}
	})
}

// summaryText: combines the most important states ("if not handled, install fails / install doesn't take effect") into the hint line at the top of the install area.
func (st *guiState) summaryText(items []statusItem) string {
	m := map[string]statusItem{}
	for _, it := range items {
		m[it.name] = it
	}
	if it, ok := m["50HX card"]; ok && !it.ok {
		return "⚠ 50HX not detected — please first confirm the card is seated and the driver is installed; otherwise install is meaningless"
	}
	var warns []string
	if it, ok := m["Secure Boot"]; ok && !it.ok {
		warns = append(warns, "Secure Boot is on, disable it in the BIOS")
	}
	if it, ok := m["Boot mode"]; ok && !it.ok {
		warns = append(warns, "Legacy+MBR boot, compute EFI cannot be installed (requires mbr2gpt to convert to GPT)")
	}
	if it, ok := m["Gen2 drivers (never deployed)"]; ok && !it.ok {
		warns = append(warns, "Gen2 drivers have never been deployed")
	}
	if it, ok := m["Gen2 logon task"]; ok && !it.ok {
		warns = append(warns, "Gen2 logon auto-start is not registered")
	}
	// Boot entry: only checked under UEFI (exists but not first / not created).
	if it, ok := m["Firmware boot entry"]; ok && !it.ok {
		if bl, ok2 := m["Boot mode"]; !ok2 || bl.ok {
			if strings.Contains(it.note, "not first") {
				warns = append(warns, "Boot entry exists but is not first, needs to be set as first in BIOS")
			} else {
				warns = append(warns, "Firmware boot entry not created")
			}
		}
	}
	if len(warns) == 0 {
		return "✓ Environment ready — missing components are auto-pre-checked, click [Install selected components] or [One-click full install]"
	}
	s := "⚠ " + strings.Join(warns, "; ")
	if r := []rune(s); len(r) > 90 {
		s = string(r[:90]) + "…"
	}
	return s
}

// envGuide: install-guide mapping "known problem → remediation steps" (echoes the v2.4 popup-text guidance style;
// only emits the steps for problems that are actually present, for log reading).
func (st *guiState) envGuide(items []statusItem) string {
	m := map[string]statusItem{}
	for _, it := range items {
		m[it.name] = it
	}
	var g []string
	if it, ok := m["50HX card"]; ok && !it.ok {
		g = append(g, "· 40HX not detected: ① confirm power and PCIe seating; ② check Device Manager for code 43 (install the driver first); ③ disable CSM in BIOS (pure UEFI), then re-scan")
	}
	if it, ok := m["Secure Boot"]; ok && !it.ok {
		g = append(g, "· Secure Boot is ON: reboot and press Del/F2 to enter BIOS -> Security/Boot -> Secure Boot=Disabled -> F10 to save -> return to the system and re-run this tool")
	}
	if it, ok := m["Boot mode"]; ok && !it.ok {
		g = append(g, "· Legacy+MBR boot: there is no EFI partition, so compute unlock cannot be installed -> run as administrator in CMD: mbr2gpt /validate /allowfullos -> mbr2gpt /convert /allowfullos -> reboot into UEFI (disable CSM) -> re-run this tool (full steps in README §2.4)")
	}
	if it, ok := m["Firmware boot entry"]; ok && !it.ok {
		if bl, ok2 := m["Boot mode"]; !ok2 || bl.ok {
			if strings.Contains(it.note, "not first") {
				g = append(g, "· Boot entry exists but is not first in displayorder: enter the BIOS and set '50HX Unlock' as the first boot entry (otherwise it may not run at boot)")
			} else {
				g = append(g, "· Firmware boot entry not created: tick [Compute EFI Deploy + firmware boot entry] above to auto-create and set it as first; if it still does not show in the BIOS list, use PE (firPE) / DiskGenius to repair the boot, or manually set the UEFI disk as the first boot device (falls back to bootx64)")
			}
		}
	}
	if it, ok := m["Gen2 drivers (never deployed)"]; ok && !it.ok {
		g = append(g, "· Gen2 drivers have never been deployed: tick [Gen2 driver deploy + Defender exclusions] to install (auto-whitelists and handles third-party AV trust prompts)")
	}
	if it, ok := m["Gen2 logon task"]; ok && !it.ok {
		g = append(g, "· Gen2 logon auto-start not registered: tick [Gen2 logon auto-start] to install; or run 50HXInstaller.exe -task as administrator")
	}
	if it, ok := m["ESP unlock EFI"]; ok && !it.ok {
		if bl, ok2 := m["Boot mode"]; !ok2 || bl.ok {
			g = append(g, "· Compute unlock EFI not deployed (if you just uninstalled / don't want compute for now: this is expected — the compute lock stays, Gen2 is unaffected; to restore compute unlock, tick [Compute EFI Deploy + firmware boot entry] above to install)")
		}
	}
	return strings.Join(g, "\n")
}

// scanOnce: runs a single read-only scan and refreshes the top hint (does not show details).
// Also outputs: environment remediation guide (known problem -> steps) and the third-party AV report — only when content changes.
func (st *guiState) scanOnce() {
	items := scanStatus()
	st.lastScan = items
	tip := st.summaryText(items)
	st.sync(func() {
		if st.tip != nil {
			st.tip.SetText(tip)
		}
	})
	// Third-party AV detection (read-only): it does not read the Defender exclusion list, the user must allow manually.
	av := hxcore.DetectThirdPartyAV()
	avKey := strings.Join(av, ",")
	if avKey != st.lastAV {
		if len(av) > 0 {
			fmt.Println("[AV] Detected third-party security software: " + strings.Join(av, " / ") +
				" — please allow the 4 driver paths in its trust/whitelist:")
			fmt.Println("        C:\\Windows\\System32\\drivers\\ThrottleStop.sys")
			fmt.Println("        C:\\Windows\\System32\\drivers\\WinRing0x64.sys")
			fmt.Println("        %ProgramData%\\50HXUnlock\\drivers\\ — ThrottleStop.sys / WinRing0x64.sys")
		}
		st.lastAV = avKey
	}
}

// applySmartDefaults: pre-check based on the latest scan — only tick missing / not-meeting-target components (already installed stays unchecked = no overwrite).
func (st *guiState) applySmartDefaults() {
	items := st.lastScan
	if len(items) == 0 {
		items = scanStatus()
		st.lastScan = items
	}
	flags := map[string]bool{}
	for _, it := range items {
		flags[it.name] = it.ok
	}
	if !flags["50HX card"] {
		fmt.Println("[i] 50HX not detected — leaving the install area fully unchecked (please first confirm the card / driver)")
		st.sync(func() {
			st.ckGsp.SetChecked(false)
			st.ckDrv.SetChecked(false)
			st.ckEfi.SetChecked(false)
			st.ckTask.SetChecked(false)
			st.ckFast.SetChecked(false)
			st.ckAspm.SetChecked(false)
			st.ckPerf.SetChecked(false)
			st.ckDefOff.SetChecked(false)
		})
		return
	}
	aspmOK := true
	if v, present := flags["PCIe ASPM"]; present {
		aspmOK = v
	}
	needGsp := !flags["GSP (EnableGpuFirmware)"]
	// Whether the drivers need to be deployed cannot be decided by only looking at the System32 files (the remove-when-done end-state is missing):
	// only install when never deployed / service is DISABLED / file is 0 bytes or size-mismatched with the backup.
	needDrv := hxcore.Gen2DriversNeedDeploy()
	needEfi := false
	if flags["Boot mode"] {
		needEfi = !flags["ESP unlock EFI"] || !flags["Firmware boot entry"]
	} else {
		fmt.Println("[i] Legacy+MBR boot: compute EFI cannot be installed — not pre-checked (requires mbr2gpt to GPT first)")
	}
	needTask := !flags["Gen2 logon task"]
	needFast := !flags["Fast Startup"]
	needAspm := !aspmOK
	needPerf := !hxcore.HighPerfPlanActive()
	// Defender real-time protection: ON -> pre-check (true to state); OFF -> no check; module missing / undetectable -> no check + a short one-time hint.
	needDefOff, defKnown := false, false
	if on, err := hxcore.DefenderRealtimeProtectionOn(); err == nil {
		defKnown = true
		needDefOff = on
	} else {
		defWarn := "No Defender management module on this machine (for third-party AV please allow the drivers in its trust list)"
		if !errors.Is(err, hxcore.ErrMpUnavailable) {
			defWarn = "Defender status query failed: " + err.Error()
		}
		if defWarn != st.lastDefWarn {
			fmt.Println("[i] " + defWarn)
			st.lastDefWarn = defWarn
		}
	}
	var pre []string
	st.sync(func() {
		// Explicit two-way setting: missing / not-meeting-target -> tick (pending action); already ready -> un-tick (no overwrite).
		// v3.0.0 fix: the old implementation only called SetChecked(true), so after install + rescan the already-ready items remained ticked.
		st.ckGsp.SetChecked(needGsp)
		if needGsp {
			pre = append(pre, "GSP")
		}
		st.ckDrv.SetChecked(needDrv)
		if needDrv {
			pre = append(pre, "Gen2 drivers")
		}
		st.ckEfi.SetChecked(needEfi)
		if needEfi {
			pre = append(pre, "Compute EFI + boot entry")
		}
		st.ckTask.SetChecked(needTask)
		if needTask {
			pre = append(pre, "Gen2 logon auto-start")
		}
		st.ckFast.SetChecked(needFast)
		if needFast {
			pre = append(pre, "Disable Fast Startup")
		}
		st.ckAspm.SetChecked(needAspm)
		if needAspm {
			pre = append(pre, "Disable ASPM")
		}
		st.ckPerf.SetChecked(needPerf)
		if needPerf {
			pre = append(pre, "High-performance plan")
		}
		wantDefOff := defKnown && needDefOff
		st.ckDefOff.SetChecked(wantDefOff)
		if wantDefOff {
			pre = append(pre, "Disable Defender real-time protection")
		}
		// The checked/unchecked state is decided by the scan above; the status and trust/whitelist notes only go into the log, not the UI labels.
	})
	if len(pre) > 0 {
		fmt.Println("[i] Pre-checked: " + strings.Join(pre, " / ") + " -> click [Install selected components] to run; the rest are already ready and remain unchecked (no overwrite)")
		return
	}
	// Nothing ticked: list the reasons on one line (all ready, ticking would overwrite / refresh).
	var ready []string
	if !needGsp {
		ready = append(ready, "GSP enabled")
	}
	if !needDrv {
		ready = append(ready, "Gen2 drivers ready")
	}
	if !flags["Boot mode"] {
		ready = append(ready, "Compute EFI (run mbr2gpt first)")
	} else if !needEfi {
		ready = append(ready, "EFI + boot entry ready")
	}
	if !needTask {
		ready = append(ready, "Auto-start registered")
	}
	if !needFast {
		ready = append(ready, "Fast Startup off")
	}
	if !needAspm {
		ready = append(ready, "ASPM off")
	}
	if !needPerf {
		ready = append(ready, "Already on High performance plan")
	}
	if defKnown && !needDefOff {
		ready = append(ready, "Defender real-time protection off")
	}
	fmt.Println("[i] All ready, nothing checked (no overwrite): " + strings.Join(ready, " | "))
}

// printDefErr: short display of Defender-related errors — a fixed short sentence + the allow-paths list when the module is missing, otherwise raw output.
func (st *guiState) printDefErr(prefix string, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, hxcore.ErrMpUnavailable) {
		fmt.Println(prefix + "No Defender management module on this machine — auto-whitelist / real-time protection toggle is unavailable")
		fmt.Println(prefix + "Third-party AV users please allow in their trust/whitelist:")
		fmt.Println("      C:\\Windows\\System32\\drivers\\ThrottleStop.sys / WinRing0x64.sys")
		fmt.Println("      %ProgramData%\\50HXUnlock\\drivers\\ — two .sys files of the same name")
		return
	}
	fmt.Println(prefix + err.Error())
}

// loadPolicyUI: reads back the current policy at startup (must be called on the UI thread — after Create, before Run).
func (st *guiState) loadPolicyUI() {
	strat := hxcore.DriverStrategy()
	for i, rb := range st.rbStrategy {
		rb.SetChecked(i == strat)
	}
	st.ckAutoHard.SetChecked(hxcore.ConfigInt("Gen2AutoHard", 1) != 0)
	cnt, interval := hxcore.Gen2RetryPolicy()
	st.neRetryCnt.SetValue(float64(cnt))
	st.neRetryMin.SetValue(float64(interval))
}

// savePolicy: writes the Gen2 policy to disk (HKLM\SOFTWARE\50HXUnlock, read by the -gen2 logon task).
func (st *guiState) savePolicy() {
	defer st.end()
	strat := 0
	for i, rb := range st.rbStrategy {
		if rb.Checked() {
			strat = i
		}
	}
	if err := hxcore.SetConfigInt("DriverStrategy", strat); err != nil {
		fmt.Println("[Policy] Save failed:", err)
		return
	}
	auto := 0
	if st.ckAutoHard.Checked() {
		auto = 1
	}
	cnt, interval := int(st.neRetryCnt.Value()), int(st.neRetryMin.Value())
	hxcore.SetConfigInt("Gen2AutoHard", auto)
	hxcore.SetConfigInt("Gen2RetryCount", cnt)
	hxcore.SetConfigInt("Gen2RetryIntervalMin", interval)
	fmt.Printf("[Policy] Saved: driver strategy=%d Gen2AutoHard=%d retries=%d / interval=%d min (active for logon task / -gen2)\n", strat, auto, cnt, interval)
	if strat == hxcore.DriverStrategyResident {
		if ok, _, _ := hxcore.TaskInfo(gen2TaskName); !ok {
			fmt.Println("[Hint] Resident guardian requires a logon auto-start task to host it: in ① tick [Gen2 logon auto-start] and click [Install selected components], or use ② [Run Gen2 and install auto-start] for a one-shot")
		} else {
			fmt.Println("[Hint] Resident guardian selected: click ② [Run Gen2 and install auto-start] (or ① [Gen2 logon auto-start]) again to refresh the task command line so it carries the guardian parameter (-guard)")
		}
	}
}

func runGUI() {
	if !isAdmin() {
		selfElevate()
		return
	}
	st := &guiState{log: &guiLog{}}

	createErr := MainWindow{
		AssignTo: &st.mw,
		Title:    "CMP 50HX Unlock Manager v3.0.0",
		MinSize:  Size{Width: 780, Height: 660},
		Size:     Size{Width: 860, Height: 800},
		Layout:   VBox{Spacing: 6},
		Children: []Widget{
			GroupBox{
				Title:  "① Components and environment setup (auto-pre-checked by current state; tick = run / refresh)",
				Layout: VBox{Spacing: 4},
				Children: []Widget{
					Label{AssignTo: &st.tip, Text: "Scanning environment..."},
					Composite{
						Layout: Grid{Columns: 2},
						Children: []Widget{
							CheckBox{AssignTo: &st.ckGsp, Text: "GSP enable (EnableGpuFirmware=1)"},
							CheckBox{AssignTo: &st.ckEfi, Text: "Compute EFI + firmware boot entry"},
							CheckBox{AssignTo: &st.ckDrv, Text: "Gen2 driver deploy + Defender exclusions"},
							CheckBox{AssignTo: &st.ckTask, Text: "Gen2 logon auto-start"},
							CheckBox{AssignTo: &st.ckFast, Text: "Power: disable Fast Startup"},
							CheckBox{AssignTo: &st.ckAspm, Text: "Power: disable PCIe link power saving"},
							CheckBox{AssignTo: &st.ckPerf, Text: "Power: High performance power plan"},
							CheckBox{AssignTo: &st.ckDefOff, Text: "Disable Defender real-time protection"},
						},
					},
					Composite{
						Layout: HBox{},
						Children: []Widget{
							PushButton{AssignTo: &st.pbInstall, Text: "Install selected components", OnClicked: func() {
								// begin grabs the lock synchronously on the UI thread: whoever wins holds it, so click-spam can't reach here
								if !st.begin("Component install") {
									return
								}
								sel := map[string]bool{
									"gsp":    st.ckGsp.Checked(),
									"drv":    st.ckDrv.Checked(),
									"efi":    st.ckEfi.Checked(),
									"task":   st.ckTask.Checked(),
									"fast":   st.ckFast.Checked(),
									"aspm":   st.ckAspm.Checked(),
									"perf":   st.ckPerf.Checked(),
									"defoff": st.ckDefOff.Checked(),
								}
								go st.installSelected(sel)
							}},
							PushButton{AssignTo: &st.pbFull, Text: "One-click full install (full flow)", OnClicked: func() {
								if !st.begin("Full install") {
									return
								}
								go func() {
									defer st.end()
									st.sync(func() { st.pbFull.SetEnabled(false) })
									defer st.sync(func() { st.pbFull.SetEnabled(true) })
									install()
									st.scanOnce() // auto-rescan after install; top hint / pre-check update accordingly
									st.applySmartDefaults()
								}()
							}},
						},
					},
				},
			},
			GroupBox{
				Title:  "② Gen2 Policy (saved = effective; the logon task and -gen2 read this — see README §2.5)",
				Layout: VBox{Spacing: 4},
				Children: []Widget{
					Label{Text: "Driver strategy: how the two drivers used for Gen2 unlock are handled after a run"},
					Label{Text: "① Remove when done (default; auto-cleaned each run, cleanest against games / anti-cheat)   ② Auto-retry on failure   ③ Resident guardian (drivers kept, checks Gen2 every minute, auto-retrains if TLS is lost)"},
					Composite{
						Layout: Grid{Columns: 3},
						Children: []Widget{
							RadioButton{AssignTo: &st.rbStrategy[0], Text: "Remove when done (default / recommended)"},
							RadioButton{AssignTo: &st.rbStrategy[1], Text: "Auto-retry on failure"},
							RadioButton{AssignTo: &st.rbStrategy[2], Text: "Resident guardian (periodic Gen2 check)"},
						},
					},
					CheckBox{AssignTo: &st.ckAutoHard, Text: "Auto-run Stage2 fallback when Gen2 is not achieved (Link Disable + PnP recovery; turning it off avoids the few-second drop on the only display card after login)"},
					Composite{
						Layout: HBox{},
						Children: []Widget{
							Label{Text: "Auto-retry on failure:"},
							NumberEdit{AssignTo: &st.neRetryCnt, MinValue: 0.0, MaxValue: 12.0, MinSize: Size{Width: 56}},
							Label{Text: "count / interval:"},
							NumberEdit{AssignTo: &st.neRetryMin, MinValue: 1.0, MaxValue: 240.0, MinSize: Size{Width: 56}},
							Label{Text: "minutes"},
						},
					},
					Composite{
						Layout: HBox{},
						Children: []Widget{
							PushButton{AssignTo: &st.pbSave, Text: "Save policy", OnClicked: func() {
								if !st.begin("Save policy") {
									return
								}
								go st.savePolicy()
							}},
							PushButton{AssignTo: &st.pbGen2, Text: "Run Gen2 now (this session only)", OnClicked: func() {
								if !st.begin("Run Gen2 now") {
									return
								}
								go func() {
									defer st.end()
									st.sync(func() { st.pbGen2.SetEnabled(false) })
									defer st.sync(func() { st.pbGen2.SetEnabled(true) })
									fmt.Println("[Gen2] Run once now (equivalent to CLI -gen2): temporarily load drivers -> unlock -> default remove-when-done.")
									fmt.Println("[Gen2] Note: this button is [effective for this session only], it does NOT install boot-time auto-start;")
									fmt.Println("[Gen2] To unlock automatically on every boot after install, click the right-hand [Run Gen2 and install auto-start], or tick ① [Gen2 logon auto-start] and install.")
									gen2Main()
									if hxcore.DriverStrategy() == hxcore.DriverStrategyResident {
										fmt.Println("[Hint] 'Resident guardian' is selected: this session has been unlocked; the per-minute self-check is carried by the logon auto-start task (effective from next login); if auto-start is not registered the guardian will not run.")
									}
									st.scanOnce() // after Gen2 the drivers / end-state may change — refresh the hint
								}()
							}},
							PushButton{AssignTo: &st.pbGen2Install, Text: "Run Gen2 and install auto-start (this session + boot auto)", OnClicked: func() {
								if !st.begin("Unlock and install auto-start") {
									return
								}
								go func() {
									defer st.end()
									st.sync(func() { st.pbGen2Install.SetEnabled(false) })
									defer st.sync(func() { st.pbGen2Install.SetEnabled(true) })
									fmt.Println("== Run Gen2 and install auto-start ==")
									fmt.Println("[Gen2] Step 1/2: first unlock this session (temporarily load drivers -> unlock -> default remove-when-done)...")
									gen2Main()
									fmt.Println("[Gen2] Step 2/2: install boot-time auto-start — driver deploy + Defender whitelist + logon task + Run key...")
									installDrivers()
									if err := hxcore.AddDefenderExclusions(); err != nil {
										st.printDefErr("  [Defender] ", err)
									} else {
										fmt.Println("  [Defender] driver files / backup directory whitelisted")
									}
									setRunKey()
									if err := setupGen2Task(); err != nil {
										fmt.Println("  [!] Logon auto-start registration failed:", err)
										fmt.Println("  [!] You can later tick [Gen2 logon auto-start] in ① and click [Install selected components] to add it")
									} else {
										fmt.Println("  [Auto-start] Registration complete — Gen2 will auto-unlock on next login (already unlocked this session, no reboot needed)")
										if hxcore.DriverStrategy() == hxcore.DriverStrategyResident {
											fmt.Println("  [Auto-start] Resident guardian enabled: the logon task will self-check Gen2 every minute, auto-retraining if TLS is lost")
										}
									}
									st.scanOnce()
								}()
							}},
						},
					},
				},
			},
			GroupBox{
				Title:  "③ Operation log (live)",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &st.teLog, ReadOnly: true, VScroll: true,
						MinSize: Size{Height: 120}, StretchFactor: 2},
				},
			},
		},
	}.Create()
	if createErr != nil {
		msgbox("50HX Installer", "GUI initialization failed: "+createErr.Error()+"\nPlease use the command-line interface (50HXInstaller.exe -h).", mbIconError)
		return
	}
	st.log.mw = st.mw
	st.log.te = st.teLog
	AttachLogSink(st.log)

	st.loadPolicyUI() // Read back Gen2 policy (UI thread, before Run).

	fmt.Println("CMP 50HX Unlock Manager v3.0.0 started (administrator).")
	go func() {
		// Open with one auto-scan: pre-check + top hint; action buttons disabled during the scan to prevent races.
		// Results are printed by applySmartDefaults ([i] pre-checked... / [i] all components already ready...).
		st.setActionsEnabled(false)
		defer st.setActionsEnabled(true)
		st.scanOnce()
		st.applySmartDefaults()
	}()
	st.mw.Run()
}

// installSelected: installs the selected components and settings (runs sequentially; all output goes to the log panel).
// Section style matches the CLI full flow; the standalone [x/8] step numbers (those are from install()'s orchestration numbering) are gone.
func (st *guiState) installSelected(sel map[string]bool) {
	defer st.end()
	st.sync(func() { st.pbInstall.SetEnabled(false) })
	defer st.sync(func() { st.pbInstall.SetEnabled(true) })
	nameOf := map[string]string{
		"gsp": "GSP enable", "drv": "Gen2 driver deploy", "efi": "Compute EFI + boot entry",
		"task": "Gen2 logon auto-start", "fast": "Disable Fast Startup", "aspm": "Disable ASPM",
		"perf": "High-performance power plan", "defoff": "Disable Defender real-time protection",
	}
	var parts []string
	for _, k := range []string{"gsp", "drv", "efi", "task", "fast", "aspm", "perf", "defoff"} {
		if sel[k] {
			parts = append(parts, nameOf[k])
		}
	}
	if len(parts) == 0 {
		fmt.Println("[i] No components / settings ticked — please tick first and then click [Install selected components]")
		return
	}
	fmt.Println("== Running: " + strings.Join(parts, " / ") + " ==")
	if sel["gsp"] {
		fmt.Println("──── GSP enable (EnableGpuFirmware=1, key to no-black-screen after unlock) ────")
		if err := enableGsp(); err != nil {
			fmt.Println("  [GSP] Failed:", err)
		} else {
			fmt.Println("  [GSP] EnableGpuFirmware=1 set (takes effect after reboot via GSP-RM)")
		}
	}
	if sel["drv"] {
		fmt.Println("──── Gen2 driver deploy + Defender exclusions (ThrottleStop/WinRing0) ────")
		installDrivers()
		if err := hxcore.AddDefenderExclusions(); err != nil {
			st.printDefErr("  [Defender] ", err)
		} else {
			fmt.Println("  [Defender] driver files / backup directory whitelisted")
		}
	}
	if sel["efi"] {
		fmt.Println("──── Compute EFI deploy + firmware boot entry (dual write + set first) ────")
		installEFI()
	}
	if sel["task"] {
		fmt.Println("──── Gen2 logon auto-start (SYSTEM task + Run key fallback) ────")
		setRunKey()
		if err := setupGen2Task(); err != nil {
			fmt.Println("  [!] Logon auto-start registration failed:", err)
			fmt.Println("  [!] You can later run as administrator: 50HXInstaller.exe -task")
		}
	}
	if sel["fast"] || sel["aspm"] || sel["perf"] {
		fmt.Println("──── Power settings (fine-grained; all revertible from the system Power Options) ────")
	}
	if sel["fast"] {
		if hxcore.FastStartupOn() {
			if err := hxcore.SetFastStartupOff(); err != nil {
				fmt.Println("  [Power] Failed to disable Fast Startup:", err)
			} else {
				fmt.Println("  [Power] Fast Startup disabled (HiberbootEnabled=0)")
			}
		} else {
			fmt.Println("  [Power] Fast Startup: was already off (OK)")
		}
	}
	if sel["aspm"] {
		if ac, dc, ok := hxcore.ASPMSavings(); !ok {
			fmt.Println("  [Power] PCIe ASPM: this machine does not expose this setting, skipping")
		} else if ac == 0 && dc == 0 {
			fmt.Println("  [Power] PCIe ASPM: was already off (OK)")
		} else {
			if err := hxcore.SetASPMOff(); err != nil {
				fmt.Println("  [Power] ASPM disable failed:", err)
			} else {
				fmt.Printf("  [Power] PCIe ASPM disabled (was AC=%d/DC=%d)\n", ac, dc)
			}
		}
	}
	if sel["perf"] {
		if hxcore.HighPerfPlanActive() {
			fmt.Println("  [Power] Power plan: already High performance (OK)")
		} else if err := hxcore.SetHighPerfPlan(); err != nil {
			fmt.Println("  [Power] Failed to switch to High performance plan:", err)
		} else {
			fmt.Println("  [Power] Switched to High performance power plan (revertible from Power Options)")
		}
	}
	if sel["defoff"] {
		fmt.Println("──── Windows Defender real-time protection ────")
		on, err := hxcore.DefenderRealtimeProtectionOn()
		if err != nil {
			st.printDefErr("  [!] ", err)
		} else if !on {
			fmt.Println("  [Defender] Real-time protection is currently off (no action needed)")
		} else if err := hxcore.SetDefenderRealtimeProtection(false); err != nil {
			st.printDefErr("  [!] ", err)
			if !errors.Is(err, hxcore.ErrMpUnavailable) {
				fmt.Println("  [!] Common cause: Windows Security Center has 'Tamper Protection' on — please disable it first and retry")
			}
		} else {
			fmt.Println("  [Defender] Real-time protection disabled")
			fmt.Println("  [Defender] Restore: in elevated PowerShell run Set-MpPreference -DisableRealtimeMonitoring $False")
		}
	}
	fmt.Println("== Done; auto-rescanning state ==")
	st.scanOnce()
	st.applySmartDefaults()
}
