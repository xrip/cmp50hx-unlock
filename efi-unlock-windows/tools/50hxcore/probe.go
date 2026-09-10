package hxcore

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

// RunOut executes a command and returns combined output (hidden window).
// All diagnostics / probing funnels through here.
func RunOut(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// FindGPU walks the PCI enum in the registry to look for the 50HX
// (VEN_10DE&DEV_1E09).
func FindGPU() bool {
	base, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Enum\PCI`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer base.Close()
	names, err := base.ReadSubKeyNames(-1)
	if err != nil {
		return false
	}
	for _, n := range names {
		if strings.Contains(n, GpuVenDev) {
			return true
		}
	}
	return false
}

// SecureBootOn reads the UEFI SecureBoot variable (1=on). If the value
// cannot be read, it is treated as off.
func SecureBootOn() bool {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	pGet := k32.NewProc("GetFirmwareEnvironmentVariableW")
	var buf [4]byte
	guid := "{8be4df61-93ca-11d2-aa0d-00e098032b8c}"
	r, _, _ := pGet.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("SecureBoot"))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(guid))),
		uintptr(unsafe.Pointer(&buf[0])), 4)
	if r == 0 {
		return false
	}
	return buf[0] == 1
}

// FirmwareIsLegacy reports whether the system booted in legacy BIOS mode
// (i.e. not UEFI).
// v2.5.1: Legacy+MBR machines have no ESP partition, so mountvol /S is
// guaranteed to fail — the root cause of the community's "EFI install
// never works" reports. GetFirmwareType requires Win8+; if the call
// fails (very old systems), it is treated as UEFI to preserve the
// existing behaviour.
func FirmwareIsLegacy() bool {
	k32 := syscall.NewLazyDLL("kernel32.dll")
	pGet := k32.NewProc("GetFirmwareType")
	var ft uint32 // FirmwareTypeUnknown=0, FirmwareTypeBios=1, FirmwareTypeUefi=2
	r, _, _ := pGet.Call(uintptr(unsafe.Pointer(&ft)))
	if r == 0 {
		return false
	}
	return ft == 1
}

// TestSigningOn precisely determines whether testsigning is enabled.
// v2.4.3: cannot use Contains("testsigning") && Contains("yes") —
// debug / isolatedcontext / flightsigning inside {current} are also Yes
// and would cause testsigning=No to be misread as on.
func TestSigningOn() bool {
	out, err := RunOut("bcdedit.exe", "/enum", "{current}")
	if err != nil {
		return false
	}
	re := regexp.MustCompile(`(?mi)^\s*testsigning\s+(yes|no)`)
	m := re.FindStringSubmatch(out)
	if len(m) == 2 {
		return strings.EqualFold(m[1], "yes")
	}
	// Fallback: line-by-line search for testsigning (tolerant of leading
	// whitespace and tabs around the field name).
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(strings.ToLower(t), "testsigning") {
			fields := strings.Fields(t)
			if len(fields) >= 2 {
				return strings.EqualFold(fields[len(fields)-1], "yes")
			}
		}
	}
	return false
}

// SetTestsigning enables test signing and verifies by reading it back.
// Returns (final enabled state, error description).
func SetTestsigning() (bool, string) {
	out, err := RunOut("bcdedit.exe", "/set", "testsigning", "on")
	if err != nil {
		return false, fmt.Sprintf("bcdedit /set testsigning on failed: %v\n%s", err, strings.TrimSpace(out))
	}
	if TestSigningOn() {
		return true, ""
	}
	return false, "bcdedit returned success but the read-back is still No\nPossible cause: testsigning cannot take effect while Secure Boot is on\nPlease disable Secure Boot in the BIOS and try again"
}

// MountESP mounts the ESP at a free drive letter; returns the letter
// (e.g. "S") or "". mountvol /S fails without admin rights → returns
// empty (safe — does not pop a UAC prompt).
func MountESP() string {
	for _, c := range []string{"Y", "X", "W", "V", "U", "T", "S"} {
		letter := c + ":"
		out, _ := RunOut("mountvol.exe", letter, "/S")
		if strings.Contains(out, "错误") || strings.Contains(out, "denied") {
			continue
		}
		if _, err := os.Stat(letter + "\\EFI"); err == nil {
			return c
		}
		if _, err := os.Stat(letter + "\\"); err == nil {
			return c
		}
	}
	return ""
}

// UnmountESP unmounts the given drive letter.
func UnmountESP(letter string) {
	if letter != "" {
		RunOut("mountvol.exe", letter+":", "/D")
	}
}
