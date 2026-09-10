package hxcore

// Structured detection of the Gen2 BYOVD drivers' deploy / install state
// — shared by the GUI page-1 scan, page-2 pre-check, the installer's
// -status flag, and the diagnostic tool. Eliminates ad-hoc "is the file
// there?" checks scattered everywhere.
//
// Deployment model (since v2.5):
//   1. Persistent backup source  %ProgramData%\50HXUnlock\drivers\*.sys
//      - installDrivers writes it on every deploy; cleanupByovd
//        (remove-when-done) does not delete it.
//      - Therefore this is the persistent "was it ever deployed?"
//        evidence; only the uninstaller removes it.
//   2. Transient deploy  %SystemRoot%\System32\drivers\*.sys + a demand
//      kernel service
//      - "Remove-when-done" (S0) / "watchdog" (S1) self-clean the file
//        and service on success →
//        file missing ≠ not installed! You have to look at the backup
//        source and the current policy to draw a conclusion.
//   3. Defender exclusion (the two .sys files + the ProgramData backup
//      directory) — protects against AV false-deletion.
//
// File-validity rules:
//   - 0-byte file = AV quarantine placeholder (present, but cannot be
//     counted as deployed).
//   - System32 file size != backup source size = replaced / corrupted
//     (needs redeploy).
//   - Service changed to DISABLED by a third-party / security product =
//     Gen2 can never start (prompt the user to repair).
//   - demand service STOPPED at rest is normal (the logon task starts
//     it); not a failure.

import (
	"os"
	"path/filepath"
)

// DrvState is the four-state model for a System32 driver file.
type DrvState int

const (
	DrvAbsent       DrvState = iota // missing
	DrvZero                         // present but 0 bytes — AV quarantine placeholder
	DrvOk                           // present and >0
	DrvSizeMismatch                 // present and >0, but size disagrees with the backup source
)

func (s DrvState) String() string {
	switch s {
	case DrvZero:
		return "0 bytes (likely AV quarantine)"
	case DrvOk:
		return "OK"
	case DrvSizeMismatch:
		return "Size differs from backup"
	default:
		return "missing"
	}
}

// DrvDeploy is the complete deploy status of one Gen2 driver.
type DrvDeploy struct {
	Service    string   // service name: ThrottleStop / WinRing0_1_2_0
	File       string   // file name: ThrottleStop.sys / WinRing0x64.sys
	BackupOK   bool     // the %ProgramData%\50HXUnlock\drivers backup source exists and is >0
	SysState   DrvState // System32 file state
	SysSize    int64
	SvcReg     bool   // service is registered
	SvcStart   string // DEMAND/AUTO/DISABLED/BOOT/SYSTEM/UNKNOWN
	SvcRunning bool   // currently RUNNING
}

type gen2Spec struct{ svc, file string }

var gen2Specs = []gen2Spec{
	{"ThrottleStop", "ThrottleStop.sys"},
	{"WinRing0_1_2_0", "WinRing0x64.sys"},
}

// PdDrvDir returns %ProgramData%\50HXUnlock\drivers (the persistent
// backup source written by the installer).
func PdDrvDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "50HXUnlock", "drivers")
}

func sysRoot() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		return r
	}
	return `C:\Windows`
}

// InspectGen2Drivers inspects each Gen2 driver one by one: backup source
// / System32 file / service. All probes are read-only (sc query/qc/stat)
// and have no side effects.
func InspectGen2Drivers() []DrvDeploy {
	out := make([]DrvDeploy, 0, len(gen2Specs))
	for _, sp := range gen2Specs {
		d := DrvDeploy{Service: sp.svc, File: sp.file}
		bp := filepath.Join(PdDrvDir(), sp.file)
		if st, _ := fileState(bp); st == DrvOk {
			d.BackupOK = true
		}
		spath := filepath.Join(sysRoot(), "System32", "drivers", sp.file)
		st, sz := fileState(spath)
		d.SysState, d.SysSize = st, sz
		if st == DrvOk && d.BackupOK {
			if fi, err := os.Stat(bp); err == nil && fi.Size() != sz {
				d.SysState = DrvSizeMismatch
			}
		}
		if reg, start, state := ServiceInfo(sp.svc); reg {
			d.SvcReg = true
			d.SvcStart = start
			d.SvcRunning = state == "RUNNING"
		}
		out = append(out, d)
	}
	return out
}

// Gen2DriversDeployedOnce: does the backup source exist? = persistent
// evidence of "the installer has ever deployed this" (System32 files get
// wiped by "remove-when-done", so they cannot answer that question).
func Gen2DriversDeployedOnce() bool {
	for _, sp := range gen2Specs {
		if st, _ := fileState(filepath.Join(PdDrvDir(), sp.file)); st == DrvOk {
			return true
		}
	}
	return false
}

// Gen2DriversNeedDeploy is the page-2 pre-check criterion — a
// (re)deploy is required if ANY of the following holds:
//   never deployed (no backup source) / service is DISABLED / System32
//   file is 0 bytes or size-mismatched with the backup.
// After "remove-when-done", System32 is missing but the backup source is
// still there → no deploy needed (the logon task auto-replays).
func Gen2DriversNeedDeploy() bool {
	if !Gen2DriversDeployedOnce() {
		return true
	}
	for _, d := range InspectGen2Drivers() {
		if d.SvcReg && d.SvcStart == "DISABLED" {
			return true
		}
		if d.SysState == DrvZero || d.SysState == DrvSizeMismatch {
			return true
		}
	}
	return false
}

func fileState(p string) (DrvState, int64) {
	fi, err := os.Stat(p)
	if err != nil {
		return DrvAbsent, 0
	}
	if fi.Size() == 0 {
		return DrvZero, 0
	}
	return DrvOk, fi.Size()
}

