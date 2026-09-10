package hxcore

// Defender driver-exclusion and real-time-protection management.
//
// Background: low-level drivers such as WinRing0x64.sys / ThrottleStop.sys
// may be quarantined by security products as HackTool/vulnerable drivers
// (a common symptom is the file being replaced by a 0-byte placeholder),
// which breaks the Gen2 auto-start. This module provides:
//   1. Whitelisting (default — scoped to this project's files, does NOT
//      disable any system protection; same-name removal on uninstall).
//   2. Optional disabling of real-time protection (high risk; only when
//      the driver is repeatedly quarantined; not checked by default).
//   3. Status queries (exclusion list / whether real-time protection is on)
//      — for scanning and UI hints.
//
// Encoding: PowerShell piped back to us returns system ANSI (GBK);
// reading it as UTF-8 directly yields mojibake (we once saw errors
// rendered as garbage). Always set [Console]::OutputEncoding=UTF8 at the
// front of every command.
//
// Compatibility: third-party AV takeovers or stripped-down systems may
// remove the Defender management module entirely; in that case
// Add/Remove/Get-MpPreference report "is not a cmdlet" — mpErr recognizes
// that pattern and emits a clear follow-up hint.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// psUtf8 forces PowerShell to emit UTF-8 to the pipe (avoids mojibake in
// the log when an error contains non-ASCII text).
const psUtf8 = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"

// Gen2DrvFiles returns the two driver filenames used by the v2.5 BYOVD.
func Gen2DrvFiles() []string {
	return []string{"ThrottleStop.sys", "WinRing0x64.sys"}
}

// ExclusionPaths returns the specific paths to whitelist
// (scoped to files/directories).
//   1-2. The two driver files under System32\drivers
//   3.   The backup source at %ProgramData%\50HXUnlock\drivers
//   4.   The current exe's directory (varies by entry point; not used
//        as a query criterion)
func ExclusionPaths() []string {
	var ps []string
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	for _, f := range Gen2DrvFiles() {
		ps = append(ps, filepath.Join(sys, "System32", "drivers", f))
	}
	ps = append(ps, PdDrvDir())
	if exe, err := os.Executable(); err == nil {
		ps = append(ps, filepath.Dir(exe))
	}
	return ps
}

// psArray builds a PowerShell array literal @('a','b') with single-quoted
// paths.
func psArray(ps []string) string {
	q := make([]string, 0, len(ps))
	for _, p := range ps {
		q = append(q, "'"+strings.ReplaceAll(p, "'", "''")+"'")
	}
	return "@(" + strings.Join(q, ",") + ")"
}

// ErrMpUnavailable indicates the Defender management module is missing
// (third-party AV takeover / stripped system removed the module). Callers
// can errors.Is against this to show a short hint instead of nesting the
// full error into the UI copy.
var ErrMpUnavailable = errors.New("Defender management module is unavailable")

// mpErr turns Defender-related command errors into plain language — the
// most common root cause is a missing module (third-party AV takeover /
// stripped system removed Defender's modules), and we surface a clear
// follow-up action.
func mpErr(action, out string, err error) error {
	low := strings.ToLower(out)
	switch {
	case strings.Contains(low, "not recognized"),
		strings.Contains(low, "commandnotfoundexception"),
		strings.Contains(out, "不是内部"),
		strings.Contains(out, "无法将"):
		return fmt.Errorf("%w: Defender management module not installed on this machine (%s)", ErrMpUnavailable, action)
	}
	msg := strings.TrimSpace(out)
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if msg != "" {
		return fmt.Errorf("%s failed: %v %s", action, err, msg)
	}
	return fmt.Errorf("%s failed: %v", action, err)
}

func runMp(cmd string) (string, error) {
	return RunOut("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psUtf8+cmd)
}

// AddDefenderExclusions is called during install — adds the driver files
// and the backup directory to the Defender exclusion list. Returns an
// error on failure (with a hint when the module is missing). When the
// drivers can load normally this is purely belt-and-suspenders protection
// against accidental deletion.
func AddDefenderExclusions() error {
	ps := ExclusionPaths()
	if len(ps) == 0 {
		return fmt.Errorf("no exclusion paths")
	}
	out, err := runMp("Add-MpPreference -ExclusionPath " + psArray(ps))
	if err != nil {
		return mpErr("Add Defender exclusions", out, err)
	}
	return nil
}

// RemoveDefenderExclusions is called during uninstall — removes the
// entries added by this tool (exact-name removal).
func RemoveDefenderExclusions() error {
	ps := ExclusionPaths()
	if len(ps) == 0 {
		return nil
	}
	out, err := runMp("Remove-MpPreference -ExclusionPath " + psArray(ps))
	if err != nil {
		return mpErr("Remove Defender exclusions", out, err)
	}
	return nil
}

// DefenderExclusionsPresent checks whether the exclusion list already
// contains the fixed items (the two System32 .sys files + the backup
// directory). Returns (all matched?, error). Query failure (e.g. module
// missing) returns an error so callers can show "unable to query".
func DefenderExclusionsPresent() (bool, error) {
	out, err := runMp("@((Get-MpPreference).ExclusionPath) | ConvertTo-Json -Compress")
	if err != nil {
		return false, mpErr("Query Defender exclusions", out, err)
	}
	out = strings.TrimSpace(out)
	if out == "" || out == "null" {
		return false, nil
	}
	var paths []string
	if strings.HasPrefix(out, "[") {
		if err := json.Unmarshal([]byte(out), &paths); err != nil {
			return false, fmt.Errorf("failed to parse Defender exclusion list: %v", err)
		}
	} else {
		// PowerShell ConvertTo-Json flattens a single-element array to a scalar.
		var s string
		if err := json.Unmarshal([]byte(out), &s); err != nil {
			return false, fmt.Errorf("failed to parse Defender exclusion list: %v", err)
		}
		paths = []string{s}
	}
	var want []string
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	for _, f := range Gen2DrvFiles() {
		want = append(want, filepath.Join(sys, "System32", "drivers", f))
	}
	want = append(want, PdDrvDir())
	trim := func(p string) string { return strings.TrimRight(strings.TrimSpace(p), `\`) }
	hit := 0
	for _, w := range want {
		for _, p := range paths {
			if strings.EqualFold(trim(p), trim(w)) {
				hit++
				break
			}
		}
	}
	return hit == len(want), nil
}

// DefenderRealtimeProtectionOn queries whether Defender real-time
// protection is currently enabled.
func DefenderRealtimeProtectionOn() (bool, error) {
	out, err := runMp("(Get-MpComputerStatus).RealTimeProtectionEnabled | ConvertTo-Json -Compress")
	if err != nil {
		return false, mpErr("Query Defender real-time protection", out, err)
	}
	switch strings.ToLower(strings.TrimSpace(out)) {
	case "true", "1":
		return true, nil
	case "false", "0", "":
		return false, nil
	}
	return false, fmt.Errorf("Query Defender real-time protection returned abnormal output: %s", strings.TrimSpace(out))
}

// SetDefenderRealtimeProtection turns real-time protection off (on=false)
// or restores it (on=true). High-risk operation — callers (the GUI) must
// require an explicit checkbox + a clear warning.
func SetDefenderRealtimeProtection(on bool) error {
	v := "False"
	act := "Disable"
	if on {
		v = "True"
		act = "Restore"
	}
	out, err := runMp("Set-MpPreference -DisableRealtimeMonitoring $" + v)
	if err != nil {
		return mpErr(act+" Defender real-time protection (rejected if Windows Security Center has Tamper Protection enabled — disable it first)", out, err)
	}
	return nil
}
