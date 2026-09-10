package hxcore

// v2.6.0: 卸载操作上提 50hxcore — GUI 组件级卸载与 50HXUninstaller.exe 共用同一实现,
// 消除两份漂移副本(原 uninstall50x 私有函数)。
// 全部为破坏性操作, 调用方(GUI 卸载页/卸载器)负责确认与提权。
// 电源设置(快速启动/ASPM)属用户偏好, 刻意不提供回滚操作 — 恢复方法见 README。

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

const bootDesc40 = "50HX Unlock"

// UninstallTaskNames: 本工具历史上用过的全部计划任务名(含 50HXGen2Retry 重试任务)
var UninstallTaskNames = []string{"50HXGen2", "50HX PCIe Gen2 Bring-up", "50HXGen2Retry", "50HXGspEnsure"}

// UninstallTasks: 删除计划任务, 返回实际删掉的名字
func UninstallTasks() []string {
	var removed []string
	for _, tn := range UninstallTaskNames {
		out, err := RunOut("schtasks.exe", "/delete", "/tn", tn, "/f")
		if err == nil || strings.Contains(out, "成功") || strings.Contains(strings.ToLower(out), "success") {
			fmt.Printf("  已删除计划任务 %s\n", tn)
			removed = append(removed, tn)
		}
	}
	return removed
}

// UninstallRunKey: 删 HKCU Run 值 50HXGen2
func UninstallRunKey() {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err == nil {
		k.DeleteValue("50HXGen2")
		k.Close()
	}
}

// UninstallBootEntry: 删固件启动项 '50HX Unlock', 返回是否删除过
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
			fmt.Printf("  已删除启动项 %s\n", curGuid)
			removed = true
			curGuid = ""
		}
	}
	return removed
}

// UninstallEspEfi: 删 \EFI\50HX\50HXUNLK.EFI; bootx64.efi 用"覆盖写+校验"从
// .50hx.bak 还原(不用 删→rename — 中间窗口会让机器起不来)。返回是否动过 ESP。
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
	// v3.0.0: EFI 运行时写的历史日志一并清除 — 否则卸载后 40HXCheck 会把它
	// 当本次日志分析, 给没装 EFI 的用户派无关引导。
	if err := os.Remove(esp + ":\\50hx_log.txt"); err == nil {
		fmt.Println("    已删除历史 EFI 日志 50hx_log.txt")
	}
	std := esp + ":\\EFI\\Boot\\bootx64.efi"
	bak := esp + ":\\EFI\\Boot\\bootx64.efi.50hx.bak"
	if data, berr := os.ReadFile(bak); berr == nil {
		if werr := os.WriteFile(std, data, 0o644); werr != nil {
			fmt.Println("  [!] 还原 bootx64.efi 写失败:", werr)
			fmt.Println("      原备份仍保留在 bootx64.efi.50hx.bak, 可手动还原")
			return removed
		}
		if rb, rerr := os.ReadFile(std); rerr == nil && len(rb) == len(data) {
			os.Remove(bak)
			fmt.Println("    已还原原 bootx64.efi (来自 .50hx.bak, 校验 OK)")
		} else {
			fmt.Println("  [!] bootx64.efi 还原后校验不一致 — 保留 .bak 供手动处理")
		}
		removed = true
	}
	return removed
}

// UninstallDriverServices: 停止并删除历史驱动服务(v2.5 BYOVD + 旧版 bridge/early)
func UninstallDriverServices() {
	for _, name := range []string{"ThrottleStop", "50hx_bridge", "50hx_early", "50hx_early-d", "WinRing0_1_2_0", "WinRing0x64", "WinRing0"} {
		RunOut("sc.exe", "stop", name)
		time.Sleep(300 * time.Millisecond)
		out, err := RunOut("sc.exe", "delete", name)
		switch {
		case err == nil || strings.Contains(strings.ToLower(out), "success") || strings.Contains(out, "成功"):
			fmt.Printf("  服务 %s 已删除\n", name)
		case strings.Contains(out, "不存在") || strings.Contains(strings.ToLower(out), "not") || strings.Contains(out, "1060"):
			fmt.Printf("  服务 %s 不存在(跳过)\n", name)
		default:
			fmt.Printf("  服务 %s 删除失败: %s\n", name, strings.TrimSpace(out))
		}
	}
}

// UninstallDriverFiles: 删 System32\drivers 下历史 .sys 与 System32\WinRing0x64.dll
func UninstallDriverFiles() {
	for _, name := range []string{"ThrottleStop.sys", "50hx_bridge.sys", "50hx_early-d.sys", "50hx_early.sys", "WinRing0x64.sys"} {
		p := os.Getenv("SystemRoot") + "\\System32\\drivers\\" + name
		if err := os.Remove(p); err != nil {
			if _, statErr := os.Stat(p); statErr == nil {
				fmt.Printf("  %s 删除失败(可能被占用, 重启后自动可删)\n", name)
			}
		} else {
			fmt.Printf("  已删除 %s\n", name)
		}
	}
	os.Remove(os.Getenv("SystemRoot") + "\\System32\\WinRing0x64.dll")
}

// UninstallGspKey: 删 EnableGpuFirmware(恢复 GSP 默认关), 返回是否删除过
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

// UninstallProgramData: 清 ProgramData\50HXUnlock (gen2_status 历史缓存 + 驱动备份)。
// gen2_status.txt 必须删 — 诊断工具会把它当"上次结果"显示, 残留 ✅ 会误导用户。
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
	// v2.6.0 修复: 策略键一并删除 — 否则卸载后 DriverStrategy/Gen2AutoHard 等
	// 残留, 重装会继承旧策略而非默认(README §2.5 承诺"卸载器会一并删除")。
	DeleteConfig()
	fmt.Println("  策略键 HKLM\\SOFTWARE\\50HXUnlock 已删除(重装回到默认策略)")
}

// CheckLeftover: 卸载收尾的残留清单(供 GUI/卸载器展示)
func CheckLeftover() []string {
	var rem []string
	if out, _ := RunOut("bcdedit.exe", "/enum", "firmware"); strings.Contains(out, bootDesc40) {
		rem = append(rem, "- 固件启动项 '50HX Unlock'(BIOS 手动删除)")
		fmt.Println("  [!] 启动项仍有残留: bcdedit /delete {guid} /f (见 BIOS 菜单)")
	} else {
		fmt.Println("  启动项: 已清理")
	}
	if k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE); err == nil {
		if _, _, e := k.GetStringValue("50HXGen2"); e == nil {
			rem = append(rem, "- Run 键 50HXGen2")
			fmt.Println("  [!] Run 键仍有残留")
		}
		k.Close()
	}
	taskLeft := false
	for _, tn := range UninstallTaskNames {
		if _, err := RunOut("schtasks.exe", "/query", "/tn", tn); err == nil {
			rem = append(rem, "- 计划任务 "+tn)
			fmt.Println("  [!] 计划任务 " + tn + " 仍有残留")
			taskLeft = true
		}
	}
	if !taskLeft {
		fmt.Println("  计划任务: 已清理")
	}
	// v3.0.0: 补查驱动服务与 System32 驱动文件 — 常驻策略/文件被占用时
	// 卸载可能只删了服务注册、文件要重启后才能删, 不能假装干净。
	svcNames := []string{"ThrottleStop", "50hx_bridge", "50hx_early", "50hx_early-d", "WinRing0_1_2_0", "WinRing0x64", "WinRing0"}
	svcLeft := false
	for _, sn := range svcNames {
		if _, err := RunOut("sc.exe", "query", sn); err == nil {
			rem = append(rem, "- 驱动服务 "+sn)
			fmt.Println("  [!] 驱动服务 " + sn + " 仍有残留(可能仍在运行, 重启后重跑卸载器)")
			svcLeft = true
		}
	}
	if !svcLeft {
		fmt.Println("  驱动服务: 已清理")
	}
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	fileLeft := false
	for _, fn := range []string{"ThrottleStop.sys", "50hx_bridge.sys", "50hx_early-d.sys", "50hx_early.sys", "WinRing0x64.sys"} {
		if _, err := os.Stat(sysRoot + "\\System32\\drivers\\" + fn); err == nil {
			rem = append(rem, "- 驱动文件 " + fn)
			fmt.Println("  [!] 驱动文件 " + fn + " 仍有残留(可能被占用, 重启后重跑卸载器)")
			fileLeft = true
		}
	}
	if !fileLeft {
		fmt.Println("  驱动文件: 已清理")
	}
	if esp := MountESP(); esp != "" {
		if _, err := os.Stat(esp + ":\\EFI\\50HX\\50HXUNLK.EFI"); err == nil {
			rem = append(rem, "- ESP 解锁 EFI 文件")
			fmt.Println("  [!] ESP 解锁 EFI 仍有残留")
		} else {
			fmt.Println("  ESP 解锁 EFI: 已清理")
		}
		if _, err := os.Stat(esp + ":\\EFI\\Boot\\bootx64.efi.50hx.bak"); err == nil {
			rem = append(rem, "- bootx64.efi.50hx.bak 备份未还原")
			fmt.Println("  [!] bootx64.efi.50hx.bak 备份仍存在")
		}
		if _, err := os.Stat(esp + ":\\50hx_log.txt"); err == nil {
			rem = append(rem, "- ESP 根 50hx_log.txt (历史 EFI 日志)")
			fmt.Println("  [!] 50hx_log.txt 历史日志仍存在(再跑一次卸载器即清除)")
		}
		RunOut("mountvol.exe", esp+":", "/D")
	}
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	pdDir := base + "\\50HXUnlock"
	if _, err := os.Stat(pdDir + "\\gen2_status.txt"); err == nil {
		rem = append(rem, "- ProgramData\\50HXUnlock\\gen2_status.txt (诊断缓存)")
		fmt.Println("  [!] gen2_status.txt 仍有残留")
	}
	if _, err := os.Stat(pdDir + "\\drivers"); err == nil {
		rem = append(rem, "- ProgramData\\50HXUnlock\\drivers (驱动备份)")
		fmt.Println("  [!] drivers 备份仍有残留")
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, ConfigKeyPath, registry.QUERY_VALUE); err == nil {
		k.Close()
		rem = append(rem, "- HKLM\\SOFTWARE\\50HXUnlock 策略键")
		fmt.Println("  [!] 策略配置键 HKLM\\SOFTWARE\\50HXUnlock 仍有残留")
	}
	return rem
}
