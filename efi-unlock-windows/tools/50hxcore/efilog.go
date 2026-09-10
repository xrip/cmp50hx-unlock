package hxcore

import (
	"os"
	"strings"
)

// AnalyzeEfiLog reads 50hx_log.txt at the root of the ESP (the EFI
// unlock-chain log) and, by classifying failure signatures, returns
// precise remediation steps. Called when SS0 stays locked; returns a
// (potentially multi-line) diagnostic recommendation string.
//
// v2.4.4 lesson from community #1 (X99 dual-card code 43) — the same
// symptom can come from different root causes:
//   A. "WPR2 NOT up" + "IMEM[0]=0xffffffff" → GPU DMA cannot reach >4GB
//      payload = motherboard Above 4G Decoding is OFF (the dev Z170 only
//      succeeded with it on).
//   B. "not-OK (m0=0x89 halted)" → booter injection failed (timing /
//      slot issue).
//   C. Log shows UNLOCKED yet SS0 is locked → driver layer overwrote it
//      (re-run the installer).
//   D. No log → EFI didn't run (boot entry not set as first / Secure Boot).
func AnalyzeEfiLog() string {
	esp := MountESP()
	if esp == "" {
		return "  [EFI log] Unable to mount the ESP (admin required) — unlock log unreadable"
	}
	defer UnmountESP(esp)
	// v3.0.0: first confirm whether the unlock EFI binary itself is
	// still present. After uninstalling the EFI, the 50hx_log.txt on the
	// ESP root is a historical leftover — running it through the
	// "booter failed / change slot / Above4G" classifier would dispatch
	// unrelated boot guidance to users without the EFI installed (real
	// community machines hit this).
	efiPath := esp + `:\EFI\50HX\50HXUNLK.EFI`
	_, efiErr := os.Stat(efiPath)
	p := esp + ":\\50hx_log.txt"
	data, err := os.ReadFile(p)
	if err != nil {
		if efiErr != nil {
			return "  [EFI log] Unlock EFI not deployed / uninstalled (no \\EFI\\50HX\\50HXUNLK.EFI and no 50hx_log.txt on the ESP)\n  Compute staying locked is expected; to unlock compute: in 50HXInstaller.exe tick [Compute EFI Deploy + firmware boot entry] and install"
		}
		return "  [EFI log] No 50hx_log.txt on the ESP — EFI may not have run\n  Enter the BIOS: set '50HX Unlock' as the first boot entry or disable Secure Boot"
	}
	if efiErr != nil {
		return "  [EFI log] Note: the 50hx_log.txt at the ESP root is a historical leftover — the unlock EFI is no longer present (uninstalled / never installed)\n  The old log does not reflect the current state; compute being locked is expected, to restore it please reinstall [Compute EFI Deploy + firmware boot entry]"
	}
	low := strings.ToLower(string(data))
	hit := func(s string) bool { return strings.Contains(low, strings.ToLower(s)) }

	// Unlock-success marker takes precedence (NOTE: "SEC2 unlocked" only
	// means the microcode is injected — it is NOT compute unlock! We must
	// match the compute-unlock signature "*** UNLOCKED ***" or the actual
	// SS0 value).
	if hit("*** unlocked ***") || hit("already unlocked (ss0/ss1 exact)") {
		return "  [EFI log] The unlock chain is actually UNLOCKED — the driver layer overwrote the state\n  Please re-run the installer (to re-set GSP) and reboot, or revert to a driver version the author has verified"
	}
	// Failure mode A: DMA cannot reach >4GB (Above 4G off).
	if hit("wpr2 not up") || (hit("imem[0]=0xffffffff") && hit("fwsec40")) {
		r := "  [EFI log] WPR2 cannot be raised + DMA reads return all-F\n"
		r += "  → GPU cannot access the >4GB unlock payload. This is a BIOS setting issue; please check each item:\n"
		r += "  1. Above 4G Decoding / 4G above decoding → Enabled ← most common!\n"
		r += "  2. Resizable BAR / Large BAR → Auto/Enabled (if the option exists)\n"
		r += "  3. Move the 50HX to the first PCIe x16 slot (CPU-direct)\n"
		r += "  4. Fast Boot → Disabled\n"
		r += "  (X99: look under Advanced / PCI Subsystem for Above 4G)"
		return r
	}
	// Failure mode B: booter HALT and final SS0 still zero (a successful
	// log may also contain attempt not-OK lines but eventually succeeds).
	if hit("final]: plm=") && hit("ss0=0x00000000") && (hit("halted") || hit("not-ok")) {
		r := "  [EFI log] booter injection failed (multiple HALTs, final SS0 still 0)\n"
		r += "  → Dual-card / non-first-slot timing issue; please check each item:\n"
		r += "  1. Move the 50HX to the first PCIe x16 slot (avoid PLX / bridges)\n"
		r += "  2. Above 4G Decoding → Enabled\n"
		r += "  3. Fast Boot → Disabled\n"
		r += "  4. If multi-card: temporarily unplug the other cards and test with only the 50HX"
		return r
	}
	// Failure mode C (v3.0): EFI cannot find the card — older versions
	// only scanned bus 0-7 / 0-16, so boards where AGESA / bridges number
	// the discrete GPU to a high bus (MSI B450 measured at bus 0x10 = 16)
	// would always miss it.
	if hit("gpu not found; abort") || hit("not found (both encodings)") {
		r := "  [EFI log] EFI cannot find the card: usually the PCI bus number is beyond the legacy scan range\n"
		r += "  (AGESA / MSI B450 etc. enumerate the discrete GPU at bus>=16, or it sits behind PLX / multi-level bridges)\n"
		r += "  → Please use the v3.0 installer to reinstall the unlock EFI (CF8 full 256-bus scan supported), then\n"
		r += "    fully power off and boot once; if it still fails, paste the full log back into the issue"
		return r
	}
	// Unknown failure: pull out the key lines for the user to paste.
	var key []string
	for _, ln := range strings.Split(string(data), "\n") {
		l := strings.ToLower(ln)
		if strings.Contains(l, "wpr2") || strings.Contains(l, "ss0") ||
			strings.Contains(l, "result") || strings.Contains(l, "not found") ||
			strings.Contains(l, "unlocked") || strings.Contains(l, "halt") {
			key = append(key, strings.TrimSpace(ln))
			if len(key) >= 5 {
				break
			}
		}
	}
	return "  [EFI log] Could not auto-classify; key lines:\n  " + strings.Join(key, "\n  ")
}
