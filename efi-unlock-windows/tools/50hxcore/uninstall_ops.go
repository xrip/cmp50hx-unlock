package hxcore

// v2.6.0: uninstall operations lifted into 50hxcore — the GUI
// component-level uninstall and 50HXUninstaller.exe share a single
// implementation, eliminating the two drifting copies (the previous
// private functions in uninstall50x).
// All of these are destructive; the caller (GUI uninstall page /
// uninstaller) is responsible for confirmation and elevation.
// Power settings (Fast Startup / ASPM) are user preferences — we
// deliberately do not provide a rollback; recovery is documented in the
// README.

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const bootDesc40 = "50HX Unlock"

// UninstallTaskNames is the complete list of scheduled task names this
// tool has ever used (including the 50HXGen2Retry retry task).
var UninstallTaskNames = []string{"50HXGen2", "50HX PCIe Gen2 Bring-up", "50HXGen2Retry", "50HXGspEnsure"}

// UninstallTasks removes the scheduled tasks; returns the names that
// were actually deleted.
func UninstallTasks() []string {
	var removed []string
	for _, tn := range UninstallTaskNames {
		out, err := RunOut("schtasks.exe", "/delete", "/tn", tn, "/f")
		if err == nil || strings.Contains(out, "成功") || strings.Contains(strings.ToLower(out), "success") {
			fmt.Printf("  Scheduled task %s removed\n", tn)
			removed = append(removed, tn)
		}
	}
	return removed
}

// UninstallRunKey deletes the HKCU Run value "50HXGen2".
func UninstallRunKey() {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err == nil {
		k.DeleteValue("50HXGen2")
		k.Close()
	}
}

// UninstallBootEntry removes the '50HX Unlock' firmware boot entry;
// returns whether anything was deleted.
func UninstallBootEntry() bool {
	out, err := RunOut("bcdedit.exe", "/enum", "firmware")
	if err != nil {
		return false
	}
	curGuid := ""
	re := regexp.MustCompile(`\{([0-9a-fA-F-]{36})\}`)
	removed := false
	for _, ln := range strings.Split(out, "\n") {
		if m := re.FindStringSubmatch(ln); len(m) > 1 {
			if strings.Contains(ln, "{") && !strings.Contains(ln, "displayorder") &&
				!strings.Contains(ln, "bootsequence") {
				curGuid = m[1]
			}
		}
		if strings.Contains(ln, bootDesc40) && curGuid != "" {
			RunOut("bcdedit.exe", "/delete", "{"+curGuid+"}", "/f")
			fmt.Printf("  Boot entry %s removed\n", curGuid)
			removed = true
			curGuid = ""
		}
	}
	return removed
}

// UninstallEspEfi removes \EFI\50HX\50HXUNLK.EFI; bootx64.efi is restored
// from .50hx.bak by "overwrite + verify" (NOT delete → rename — the
// in-between window would prevent the machine from booting). Returns
// whether the ESP was touched.
func UninstallEspEfi() bool {
	esp := MountESP()
	if esp == "" {
		return false
	}
	defer RunOut("mountvol.exe", esp+":", "/D")
	removed := false
	target := esp + ":\\EFI\\50HX\\50HXUNLK.EFI"
	if err := os.Remove(target); err == nil {
		removed = true
	}
	if entries, err := os.ReadDir(esp + ":\\EFI\\40HX"); err == nil && len(entries) == 0 {
		os.Remove(esp + ":\\EFI\\40HX")
	}
	// v3.0.0: also clear the historical log written by the EFI runtime
	// — otherwise 40HXCheck will read it as the current log and dispatch
	// unrelated boot guidance to users without the EFI installed.
	if err := os.Remove(esp + ":\\50hx_log.txt"); err == nil {
		fmt.Println("    Historical EFI log 50hx_log.txt removed")
	}
	std := esp + ":\\EFI\\Boot\\bootx64.efi"
	bak := esp + ":\\EFI\\Boot\\bootx64.efi.50hx.bak"
	if data, berr := os.ReadFile(bak); berr == nil {
		if werr := os.WriteFile(std, data, 0o644); werr != nil {
			fmt.Println("  [!] bootx64.efi restore write failed:", werr)
			fmt.Println("      Original backup remains at bootx64.efi.50hx.bak, can be restored manually")
			return removed
		}
		if rb, rerr := os.ReadFile(std); rerr == nil && len(rb) == len(data) {
			os.Remove(bak)
			fmt.Println("    Original bootx64.efi restored (from .50hx.bak, verify OK)")
		} else {
			fmt.Println("  [!] bootx64.efi verification mismatch after restore — keeping .bak for manual handling")
		}
		removed = true
	}
	return removed
}

// UninstallDriverServices stops and removes the historical driver services
// (v2.5 BYOVD + legacy bridge/early).
func UninstallDriverServices() {
	for _, name := range []string{"ThrottleStop", "50hx_bridge", "50hx_early", "50hx_early-d", "WinRing0_1_2_0", "WinRing0x64", "WinRing0"} {
		RunOut("sc.exe", "stop", name)
		time.Sleep(300 * time.Millisecond)
		out, err := RunOut("sc.exe", "delete", name)
		switch {
		case err == nil || strings.Contains(strings.ToLower(out), "success") || strings.Contains(out, "成功"):
			fmt.Printf("  Service %s removed\n", name)
		case strings.Contains(out, "不存在") || strings.Contains(strings.ToLower(out), "not") || strings.Contains(out, "1060"):
			fmt.Printf("  Service %s not present (skipped)\n", name)
		default:
			fmt.Printf("  Service %s delete failed: %s\n", name, strings.TrimSpace(out))
		}
	}
}

// UninstallDriverFiles removes the legacy .sys files under System32\drivers
// and System32\WinRing0x64.dll.
func UninstallDriverFiles() {
	for _, name := range []string{"ThrottleStop.sys", "50hx_bridge.sys", "50hx_early-d.sys", "50hx_early.sys", "WinRing0x64.sys"} {
		p := os.Getenv("SystemRoot") + "\\System32\\drivers\\" + name
		if err := os.Remove(p); err != nil {
			if _, statErr := os.Stat(p); statErr == nil {
				fmt.Printf("  %s delete failed (may be in use; will be removable after reboot)\n", name)
			}
		} else {
			fmt.Printf("  %s removed\n", name)
		}
	}
	os.Remove(os.Getenv("SystemRoot") + "\\System32\\WinRing0x64.dll")
}

// UninstallGspKey removes EnableGpuFirmware (restores GSP to its default
// off state); returns whether anything was deleted.
func UninstallGspKey() bool {
	key := FindGpuClassKey()
	if key == "" {
		return false
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	if err := k.DeleteValue("EnableGpuFirmware"); err != nil {
		return false
	}
	return true
}

// UninstallProgramData clears ProgramData\50HXUnlock (gen2_status
// historical cache + driver backup).
// gen2_status.txt MUST be removed — the diagnostic tool surfaces it as
// the "last result"; leaving a residual ✅ would mislead the user.
func UninstallProgramData() {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	dir := base + "\\50HXUnlock"
	_ = os.Remove(dir + "\\gen2_status.txt")
	_ = os.RemoveAll(dir + "\\drivers")
	if entries, err := os.ReadDir(dir); err == nil && len(entries) == 0 {
		os.Remove(dir)
	}
	// v2.6.0 fix: also remove the policy key — otherwise
	// DriverStrategy / Gen2AutoHard etc. linger after uninstall and the
	// reinstall inherits the old policy instead of the defaults (README
	// §2.5 promises "the uninstaller removes them too").
	DeleteConfig()
	fmt.Println("  Policy key HKLM\\SOFTWARE\\50HXUnlock removed (reinstall returns to default policy)")
}

// CheckLeftover returns a leftover list for the post-uninstall summary
// (displayed by the GUI / uninstaller).
func CheckLeftover() []string {
	var rem []string
	if out, _ := RunOut("bcdedit.exe", "/enum", "firmware"); strings.Contains(out, bootDesc40) {
		rem = append(rem, "- Firmware boot entry '50HX Unlock' (delete from BIOS)")
		fmt.Println("  [!] Boot entry still present: bcdedit /delete {guid} /f (also see BIOS menu)")
	} else {
		fmt.Println("  Boot entry: cleaned")
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE); err == nil {
		if _, _, e := k.GetStringValue("50HXGen2"); e == nil {
			rem = append(rem, "- Run key 50HXGen2")
			fmt.Println("  [!] Run key still present")
		}
		k.Close()
	}
	taskLeft := false
	for _, tn := range UninstallTaskNames {
		if _, err := RunOut("schtasks.exe", "/query", "/tn", tn); err == nil {
			rem = append(rem, "- Scheduled task "+tn)
			fmt.Println("  [!] Scheduled task " + tn + " still present")
			taskLeft = true
		}
	}
	if !taskLeft {
		fmt.Println("  Scheduled tasks: cleaned")
	}
	// v3.0.0: also probe driver services and System32 driver files —
	// under the resident policy or when files are in use, uninstall may
	// only have removed the service registration, with the files only
	// deletable after a reboot. Don't pretend it's clean.
	svcNames := []string{"ThrottleStop", "50hx_bridge", "50hx_early", "50hx_early-d", "WinRing0_1_2_0", "WinRing0x64", "WinRing0"}
	svcLeft := false
	for _, sn := range svcNames {
		if _, err := RunOut("sc.exe", "query", sn); err == nil {
			rem = append(rem, "- Driver service "+sn)
			fmt.Println("  [!] Driver service " + sn + " still present (may still be running; reboot and re-run uninstaller)")
			svcLeft = true
		}
	}
	if !svcLeft {
		fmt.Println("  Driver services: cleaned")
	}
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	fileLeft := false
	for _, fn := range []string{"ThrottleStop.sys", "50hx_bridge.sys", "50hx_early-d.sys", "50hx_early.sys", "WinRing0x64.sys"} {
		if _, err := os.Stat(sysRoot + "\\System32\\drivers\\" + fn); err == nil {
			rem = append(rem, "- Driver file " + fn)
			fmt.Println("  [!] Driver file " + fn + " still present (may be in use; reboot and re-run uninstaller)")
			fileLeft = true
		}
	}
	if !fileLeft {
		fmt.Println("  Driver files: cleaned")
	}
	if esp := MountESP(); esp != "" {
		if _, err := os.Stat(esp + ":\\EFI\\50HX\\50HXUNLK.EFI"); err == nil {
			rem = append(rem, "- ESP unlock EFI file")
			fmt.Println("  [!] ESP unlock EFI still present")
		} else {
			fmt.Println("  ESP unlock EFI: cleaned")
		}
		if _, err := os.Stat(esp + ":\\EFI\\Boot\\bootx64.efi.50hx.bak"); err == nil {
			rem = append(rem, "- bootx64.efi.50hx.bak backup not restored")
			fmt.Println("  [!] bootx64.efi.50hx.bak backup still present")
		}
		if _, err := os.Stat(esp + ":\\50hx_log.txt"); err == nil {
			rem = append(rem, "- ESP root 50hx_log.txt (historical EFI log)")
			fmt.Println("  [!] 50hx_log.txt historical log still present (run uninstaller once more to clear)")
		}
		RunOut("mountvol.exe", esp+":", "/D")
	}
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	pdDir := base + "\\50HXUnlock"
	if _, err := os.Stat(pdDir + "\\gen2_status.txt"); err == nil {
		rem = append(rem, "- ProgramData\\50HXUnlock\\gen2_status.txt (diagnostic cache)")
		fmt.Println("  [!] gen2_status.txt still present")
	}
	if _, err := os.Stat(pdDir + "\\drivers"); err == nil {
		rem = append(rem, "- ProgramData\\50HXUnlock\\drivers (driver backup)")
		fmt.Println("  [!] drivers backup still present")
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, ConfigKeyPath, registry.QUERY_VALUE); err == nil {
		k.Close()
		rem = append(rem, "- HKLM\\SOFTWARE\\50HXUnlock policy key")
		fmt.Println("  [!] Policy config key HKLM\\SOFTWARE\\50HXUnlock still present")
	}
	return rem
}
