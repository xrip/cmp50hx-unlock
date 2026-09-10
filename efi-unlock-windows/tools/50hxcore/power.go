package hxcore

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// v2.5.1: two system power settings that affect "stability of the
// unlock-at-boot chain".
// Source: community v2.4.5-era troubleshooting conclusions + v2.5
// issues #1 / #3 feedback —
//  1. Fast Startup (hybrid hibernate): "shutdown → power on" reuses the
//     hibernate resume and skips the full UEFI boot, so the unlock EFI
//     may not run → "installed but nothing happens / compute still
//     locked".
//  2. PCIe Link State Power Management (ASPM): when enabled, the GPU is
//     downshifted to Gen1 when idle, which makes post-login reads easily
//     false-report "Gen2 failed" (load auto-restores Gen2 in practice).
// Both only affect power behaviour, never touch system protection;
// either can be reverted from the original Settings UI / command.

// FastStartupOn reports whether Windows Fast Startup (hybrid hibernate)
// is enabled (HiberbootEnabled=1).
// Missing key (very old systems / hibernate not enabled) is treated as off.
func FastStartupOn() bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Power`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("HiberbootEnabled")
	if err != nil {
		return false
	}
	return v == 1
}

// SetFastStartupOff disables Fast Startup (only the hybrid-hibernate
// behaviour — hibernate itself is preserved).
func SetFastStartupOff() error {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\Session Manager\Power`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue("HiberbootEnabled", 0)
}

var rePowerIdx = regexp.MustCompile(`0x([0-9a-fA-F]{8})`)

// ASPMSavings returns the current power plan's PCIe Link State Power
// Management (ASPM) setting.
// Returns (AC, DC, detectable). 0=off, 1=moderate savings, 2=maximum savings.
func ASPMSavings() (uint32, uint32, bool) {
	out, err := RunOut("powercfg", "-q", "SCHEME_CURRENT", "SUB_PCIEXPRESS", "ASPM")
	if err != nil || !strings.Contains(out, "ee12f906") {
		return 0, 0, false
	}
	// The last two 0x???????? values in the output are the AC / DC
	// current indices (the "Possible Settings Index" line has no 0x
	// prefix and won't be picked up; output format is the same in
	// English and Chinese locales).
	m := rePowerIdx.FindAllStringSubmatch(out, -1)
	if len(m) < 2 {
		return 0, 0, false
	}
	ac, _ := strconv.ParseUint(m[len(m)-2][1], 16, 32)
	dc, _ := strconv.ParseUint(m[len(m)-1][1], 16, 32)
	return uint32(ac), uint32(dc), true
}

// SetASPMOff sets the current power plan's PCIe Link State Power
// Management to off (AC + DC, applied immediately).
func SetASPMOff() error {
	for _, cmd := range [][]string{
		{"-setacvalueindex", "SCHEME_CURRENT", "SUB_PCIEXPRESS", "ASPM", "0"},
		{"-setdcvalueindex", "SCHEME_CURRENT", "SUB_PCIEXPRESS", "ASPM", "0"},
		{"-setactive", "SCHEME_CURRENT"},
	} {
		out, err := RunOut("powercfg", cmd...)
		if err != nil {
			return fmt.Errorf("powercfg %s: %s", cmd[0], strings.TrimSpace(out))
		}
	}
	return nil
}

// High-performance power plan GUID (Windows built-in, identical across
// all locales).
const highPerfPlanGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"

// HighPerfPlanActive reports whether the active power plan is already
// "High performance".
func HighPerfPlanActive() bool {
	out, err := RunOut("powercfg", "/getactivescheme")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(out), highPerfPlanGUID)
}

// SetHighPerfPlan switches to the High performance power plan
// (reversible any time via Power Options — non-destructive).
func SetHighPerfPlan() error {
	out, err := RunOut("powercfg", "/setactive", highPerfPlanGUID)
	if err != nil {
		return fmt.Errorf("failed to switch to High performance power plan: %s", strings.TrimSpace(out))
	}
	return nil
}
