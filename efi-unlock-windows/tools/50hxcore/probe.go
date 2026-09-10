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

// RunOut: 执行命令并返回合并输出(隐藏窗口)。诊断/探测统一走这里。
func RunOut(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// FindGPU: registry 扫 PCI 枚举找 50HX (VEN_10DE&DEV_1E09)
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

// SecureBootOn: 读 UEFI SecureBoot 变量 (1=开)。读不到视为关。
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

// FirmwareIsLegacy: 系统是否以传统 BIOS(Legacy) 方式引导 (非 UEFI)。
// v2.5.1: Legacy+MBR 机器没有 ESP 分区, mountvol /S 必然失败 —
// 这是社区"EFI 装不上"的根因。GetFirmwareType 需 Win8+; 调用失败
// (极老系统)按 UEFI 处理, 保持原有行为。
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

// TestSigningOn: 精确判断 testsigning 是否开启。
// v2.4.3: 不能 Contains("testsigning")&&Contains("yes") — {current} 里
// debug/isolatedcontext/flightsigning 也是 Yes, 会把 testsigning No 误判成开。
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
	// 兜底: 逐行找 testsigning (容忍字段名前后空白/制表)
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

// SetTestsigning: 开启测试签名并读回验证。返回 (最终是否开启, 错误说明)。
func SetTestsigning() (bool, string) {
	out, err := RunOut("bcdedit.exe", "/set", "testsigning", "on")
	if err != nil {
		return false, fmt.Sprintf("bcdedit /set testsigning on 失败: %v\n%s", err, strings.TrimSpace(out))
	}
	if TestSigningOn() {
		return true, ""
	}
	return false, "bcdedit 返回成功但读回仍为 No\n可能原因: Secure Boot 开启时 testsigning 无法生效\n请进 BIOS 关闭 Secure Boot 后重试"
}

// MountESP: 挂 ESP 到空闲盘符, 返回盘符字母(如 "S")或 ""。
// 非管理员下 mountvol /S 失败 → 返回空(安全, 不弹 UAC)。
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

// UnmountESP: 卸载盘符。
func UnmountESP(letter string) {
	if letter != "" {
		RunOut("mountvol.exe", letter+":", "/D")
	}
}
