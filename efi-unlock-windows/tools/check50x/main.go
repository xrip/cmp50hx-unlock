// 40HXCheck — CMP 50HX 解锁独立诊断工具 v3.0.0
//
// 双击即诊, 只读为主; v2.5 起若发现"算力/Gen2 无法实测(驱动未运行)"且驱动文件
// 在包内, 会临时拉起 ThrottleStop + WinRing0 实测后自清理(用完即卸, 保持无痕):
//
//	① 最优先显示: 算力解锁状态 + PCIe Gen2 状态
//	② 其次: GPU/Secure Boot/GSP/测试签名
//	③ 明细与建议
//
// 安装器(40HXInstaller)负责"装", 本工具负责"查"。
//
// 实现共享 tools/50hxcore (与安装器同一份探测/诊断代码, 不会漂移)。
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
	appTitle     = "CMP 50HX 解锁诊断"
	logsDirName  = "50HXUnlock"              // %LOCALAPPDATA%\50HXUnlock\logs
	gen2TaskName = "50HX PCIe Gen2 Bring-up" // 与安装器 setupGen2Task 同名
)

var (
	procMsgBoxW = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
)

// ---- v2.5: 临时驱动管理 (ThrottleStop + WinRing0, 用完即卸) ----
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

// driverSrcDir: 在包结构中定位 drivers/ (v2.5: exe 旁 gen2/drivers / ProgramData 备份)。
func driverSrcDir() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	pd := filepath.Join(os.Getenv("ProgramData"), "50HXUnlock", "drivers") // 安装器留下的备份源
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

// throttleStopAppRunning: 本机是否正在运行 ThrottleStop 软件(同名驱动共存, 不删它的)。
func throttleStopAppRunning() bool {
	out, _ := hxcore.RunOut("tasklist.exe", "/fi", "imagename eq ThrottleStop.exe")
	return strings.Contains(out, "ThrottleStop.exe")
}

// ensureDrivers: 确保 TS/WinRing0 服务 RUNNING。已运行→不管(外部管理);
// 否则从包 drivers 部署+启动。
// 返回 (deployed 本工具是否部署/尝试拉起过, ok 是否两个都在运行, fail 拉起失败线索)。
// 杀软隔离常把 .sys 替换成 0 字节占位(文件仍在)→ 仅判"不存在"会漏, 故按
// 缺失/0字节自愈重部署; 重部署后补 Defender 排除防再删。
// 说明: "拉起"本身就是一次驱动加载测试 — 失败大多能归因(见 classifyLoadErr)。
func ensureDrivers() (deployed bool, ok bool, fail string) {
	src := driverSrcDir()
	allRunning := svcState(svcTS) == "RUNNING" && svcState(svcWR) == "RUNNING"
	if allRunning {
		return false, true, ""
	}
	if src == "" {
		return false, false, "发布包内未找到可临时拉起的驱动目录(gen2\\drivers)"
	}
	var fails []string
	for _, d := range []struct{ svc, file string }{
		{svcTS, fileTS}, {svcWR, fileWR},
	} {
		dst := filepath.Join(sysDrvDir(), d.file)
		if b, e := os.ReadFile(dst); e != nil || len(b) == 0 {
			if sb, e2 := os.ReadFile(filepath.Join(src, d.file)); e2 == nil {
				os.WriteFile(dst, sb, 0o644)
				_ = hxcore.AddDefenderExclusions() // best-effort 防再删
			}
		}
		if svcState(d.svc) == "RUNNING" {
			continue
		}
		deployed = true
		hxcore.RunOut("sc.exe", "create", d.svc, "type=", "kernel",
			"start=", "demand", "binPath=", `\SystemRoot\System32\drivers\`+d.file)
		if _, err := hxcore.RunOut("sc.exe", "start", d.svc); err != nil {
			// 服务可能被标记为删除(1072)/禁用(1058)→ 清标记后重建+启动一次
			// (对齐安装器 ensureSvcLoaded; 卸载残留态下诊断也能自愈加载)
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

// classifyLoadErr: 把"驱动拉起失败"的原始错误转成用户能懂的归因与处理。
func classifyLoadErr(raw string) string {
	r := strings.ToLower(raw)
	switch {
	case strings.Contains(r, "1275"):
		return "Windows 安全设置阻止了驱动加载(错误 1275)——多为 Defender 的『内核隔离/内存完整性』、『易受攻击驱动程序阻止列表』或 Smart App Control 开启; 请到 Windows 安全中心临时关闭这些保护后重试(加载完可再开)"
	case strings.Contains(r, "577"):
		return "驱动映像被系统拒绝(错误 577)——文件被改动或安全策略拦截; 请重跑 40HXInstaller 重新部署原版驱动, 并检查安全中心的『不受信任驱动』设置"
	case strings.Contains(r, "1058"):
		return "服务被禁用(错误 1058)——本工具已尝试改回并重建"
	case strings.Contains(r, "1072"):
		return "服务处于『标记删除』残留态(错误 1072)——本工具已重建重试"
	case strings.Contains(r, "拒绝访问"), strings.Contains(r, "access is denied"), strings.Contains(r, "error 5"), strings.Contains(r, " 5:"):
		return "权限不足(错误 5)——请以管理员身份运行本工具"
	case strings.Contains(r, "1060"), strings.Contains(r, "不存在"):
		return "服务未找到(错误 1060)——驱动文件未部署成功, 重跑安装器后重试"
	}
	return "驱动启动失败——多因第三方杀软的 HIPS/驱动拦截, 请到其信任/白名单放行两个 .sys 后重试; 仍不行发日志给作者"
}

// cleanupDrivers: 自清理 — 停服务、删服务、删驱动文件(保持无痕, 不给反作弊留磁盘残留)。
// 本机 ThrottleStop 软件正在用该驱动时不删(避免打断用户软件)。
func cleanupDrivers() {
	if throttleStopAppRunning() {
		return
	}
	// 尊重驱动运行策略: "常驻"时本工具绝不卸; 其余(用完即卸/失败自动重试)正常自清理。
	switch hxcore.DriverStrategy() {
	case hxcore.DriverStrategyResident:
		fmt.Println("  常驻策略: 保留驱动服务与文件(诊断不清理)")
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

// isAdmin: 与安装器同款实现 (TokenElevation 在受限环境可能误报 0, 再试 SCM 全权)
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

// selfElevate: 非管理员时 ShellExecute runas 提权重启(诊断要挂 ESP 读 50hx_log)
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
		msgbox("需要管理员权限才能读取 EFI 解锁日志(50hx_log.txt)。\n请右键本程序 -> 以管理员身份运行。", 0x30)
	}
	os.Exit(0)
}

// logsDir: %LOCALAPPDATA%\50HXUnlock\logs (统一日志收集目录, 用户好找)
func logsDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	d := filepath.Join(base, logsDirName, "logs")
	os.MkdirAll(d, 0o755)
	return d
}

// collectLogs: 把相关日志汇集到固定目录, 返回目录路径
func collectLogs(diagSnapshot string) string {
	dir := logsDir()
	// 1. 安装器/Gen2 日志 (%TEMP%\50HX_installer.log)
	if b, err := os.ReadFile(filepath.Join(os.TempDir(), "50HX_installer.log")); err == nil {
		os.WriteFile(filepath.Join(dir, "installer.log"), b, 0o644)
	}
	// 2. EFI 解锁链日志 (ESP 根 50hx_log.txt) — 管理员下可读;
	//    v3.0.0: 仅当解锁 EFI 本体还在时才收集 — 卸载 EFI 后该文件是历史残留,
	//    拷进 logs 会在回溯时被误当"本次 EFI 运行日志"。
	if esp := hxcore.MountESP(); esp != "" {
		if _, efiErr := os.Stat(esp + `:\EFI\50HX\50HXUNLK.EFI`); efiErr == nil {
			if b, err := os.ReadFile(esp + ":\\50hx_log.txt"); err == nil {
				os.WriteFile(filepath.Join(dir, "50hx_log.txt"), b, 0o644)
			}
		}
		hxcore.UnmountESP(esp)
	}
	// 3. 本次诊断快照(最新) + 时间戳归档(保留历史便于对比)
	os.WriteFile(filepath.Join(dir, "diagnose.txt"), []byte(diagSnapshot), 0o644)
	ts := time.Now().Format("20060102_150405")
	os.WriteFile(filepath.Join(dir, "diagnose_"+ts+".txt"), []byte(diagSnapshot), 0o644)
	return dir
}

// indentLines: 多行文本统一加 4 空格缩进(状态文件内容展示用)
func indentLines(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, ln := range lines {
		lines[i] = "    " + ln
	}
	return strings.Join(lines, "\n")
}

// copyToClipboard: PowerShell Set-Clipboard(失败静默 — 仅增强, 不阻塞)
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

// ---- v2.6.0: 加强诊断快照, 便于社区反馈定位 ----
// 环境/驱动/原始 PCIe 寄存器/已知限制 四段富文本, 写入 diagnose.txt 与剪贴板。

// osVersion: Windows 版本/构建号 (cmd /c ver)
func osVersion() string {
	out, _ := hxcore.RunOut("cmd.exe", "/c", "ver")
	out = strings.TrimSpace(out)
	if out == "" {
		out = "未知"
	}
	arch := os.Getenv("PROCESSOR_ARCHITECTURE")
	if arch == "" {
		arch = "?"
	}
	return fmt.Sprintf("%s [%s]", out, arch)
}

// driverDetail: 单驱动的部署详情 — 数据源 = hxcore.InspectGen2Drivers(),
// 与安装器 GUI 页① / -status 完全同一套状态判定(备份源 / System32 四态 /
// 服务注册与启动类型 / 运行态), 保证"诊断与安装器对同一台机器说法一致"。
func driverDetail(svc, file string) string {
	for _, d := range hxcore.InspectGen2Drivers() {
		if d.Service != svc || d.File != file {
			continue
		}
		sysS := "System32缺失"
		switch d.SysState {
		case hxcore.DrvZero:
			sysS = "System32 0字节 ⚠杀软隔离占位"
		case hxcore.DrvSizeMismatch:
			sysS = fmt.Sprintf("System32大小=%d字节 ⚠与备份不一致(被替换?)", d.SysSize)
		case hxcore.DrvOk:
			sysS = fmt.Sprintf("System32大小=%d字节", d.SysSize)
		}
		svcS := "服务未注册"
		if d.SvcReg {
			svcS = "服务" + d.SvcStart
			if d.SvcStart == "DISABLED" {
				svcS += " ⚠被禁用(Gen2 拉不起, 重跑安装器修复)"
			} else if d.SvcRunning {
				svcS += "/运行中"
			} else {
				svcS += "(demand, 待登录任务拉起)"
			}
		}
		backS := "无备份源(从未安装)"
		if d.BackupOK {
			backS = "备份源OK(曾部署)"
			if d.SysState == hxcore.DrvAbsent && !d.SvcReg {
				backS += "; 用完即卸已自清理属正常, 下次登录自动重部署"
			}
		}
		return fmt.Sprintf("  %-16s %s | %s | %s\n", d.File, sysS, svcS, backS)
	}
	return fmt.Sprintf("  %-16s (状态检测未覆盖)\n", file)
}

// spdName: PCIe 链路速率编码 → 名称
func spdName(s uint32) string {
	names := []string{"?", "Gen1(2.5GT/s)", "Gen2(5GT/s)", "Gen3(8GT/s)", "Gen4(16GT/s)", "Gen5"}
	if s >= uint32(len(names)) {
		return "?"
	}
	return names[s]
}

// rawPcieDump: 原始 PCIe 链路寄存器 + BAR0 BOOT_0 (Gen2 定位核心证据)
func rawPcieDump() string {
	wh, err := hxcore.OpenDevice(`\\.\WinRing0_1_2_0`)
	if err != nil {
		return "  (WinRing0 不可用, 跳过原始寄存器读取)\n"
	}
	defer hxcore.CloseHandle(wh)
	bdf, ok := hxcore.FindGPUPCI(wh)
	if !ok {
		return "  (FindGPUPCI 未定位 40HX, 跳过)\n"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  BDF=0x%05X (bus=%d dev=%d fn=%d)\n", bdf,
		(bdf>>8)&0xFF, (bdf>>3)&0x1F, bdf&0x7))
	cap := hxcore.PcieCap(wh, bdf)
	if cap == 0 {
		return sb.String() + "  (无 PCIe Capability)\n"
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
	sb.WriteString(fmt.Sprintf("  LNKSTA =0x%08X 当前=%s 宽度=x%d\n", lnksta, spdName(lnksta&0xF), (lnksta>>4)&0x3F))
	sb.WriteString(fmt.Sprintf("  LNKCTL2=0x%08X 目标=%s\n", lnkctl2, spdName(lnkctl2&0xF)))
	sb.WriteString(fmt.Sprintf("  LNKSTA2=0x%08X\n", lnksta2))
	// BAR0 BOOT_0 — 确认 BAR0 真指向 50HX MMIO
	if bar0raw, e := hxcore.PciRd(wh, bdf, 0x10); e == nil {
		bar0 := uint64(bar0raw & 0xFFFFFFF0)
		th, e2 := hxcore.OpenThrottleStop()
		if e2 == nil {
			defer hxcore.CloseHandle(th)
			if v, e3 := hxcore.TSRead(th, bar0+0x0); e3 == nil {
				fam := (v >> 24) & 0xFF
				tag := "未知"
				if fam == 0x16 {
					tag = "TU10x (50HX OK)"
				}
				sb.WriteString(fmt.Sprintf("  BAR0+0x00 BOOT_0=0x%08X (家族=0x%02X %s)\n", v, fam, tag))
			} else {
				sb.WriteString(fmt.Sprintf("  BAR0+0x00 BOOT_0 读取失败: %v\n", e3))
			}
		} else {
			sb.WriteString("  (ThrottleStop 不可用, 跳过 BOOT_0)\n")
		}
	}
	return sb.String()
}

// knownIssuesBlock: 已知限制/潜在问题 — 社区反馈时对照
func knownIssuesBlock() string {
	var sb strings.Builder
	sb.WriteString("\n--- 已知限制 / 潜在问题 (v3.0.0, 社区未全覆盖项) ---\n")
	sb.WriteString("· 驱动/GSP 持有链路策略(GSP-RM): 空闲/低负载时 nvlddmkm 把 GPU 侧 TLS 回写 Gen1; Stage2 自动回退或 LD(-hard) 可解除。已确认**不是固件写保护**(批次号 .06/.04 不能当判据), **不要刷 VBIOS** — 仍失败发诊断与日志反馈作者。\n")
	sb.WriteString("· 寨板/多卡: retrain-only 在部分主板/拓扑训不上 Gen2, 需 Root Link Disable 回退(瞬断链路)。v2.6 登录任务默认已自动尝试一次 Stage2(Gen2AutoHard); 仍失败可手动 `50HXInstaller.exe -gen2 -hard`。\n")
	sb.WriteString("· EFI 找不到卡(旧版只扫 bus 0-7): v3.0 已扩到 0-16 + CF8 全 0-255 兜底, 覆盖 AGESA/高总线(微星 B450 实测 bus 0x10); 若重装 v3.0 EFI 后仍 not found, 多为固件没初始化该无头槽 — 走 BIOS: Above4G+Re-Size BAR / Init Display First=PEG / 插 CPU 顶槽, 并把 50hx_log.txt(含 \"diag: CF8 visible devices\" 设备映射段)发作者。\n")
	sb.WriteString("· 空闲省电降速: 负载低时链路降到 Gen1 属正常, 负载自动回 Gen2; 诊断 TLS=Gen2 即配置成功, 非失败。\n")
	sb.WriteString("· ThrottleStop 软件共存: 本工具驱动与 ThrottleStop 同名, 自动复用其驱动、不删除不打断; 若冲突可关闭 ThrottleStop 后重跑。\n")
	sb.WriteString("· 杀软隔离: 第三方杀软可能隔离驱动 .sys; 已加 Defender 排除, 其他杀软请在安全中心放行本项目文件。\n")
	sb.WriteString("· 驱动签名: 改名重编的 .sys 会丢失原签名, 需测试签名/EV 证书; 正式发布件保持原签名。\n")
	sb.WriteString("· 报告 issue 时请附: 本诊断 txt + %TEMP%\\50HX_installer.log + 主板/CPU/GPU/系统版本。\n")
	return sb.String()
}

// drvLogEvidence: 驱动加载不了(drvOK=false)时, 回读历史日志判断"驱动是否曾经成功运行过",
// 返回 (everRan 是否曾成功, summary 摘要). 用于给出针对性建议而非笼统"驱动未就绪" —
// 社区反馈时据此区分"解锁已生效只是本次无权限确认" vs "从未部署需重装"。
func drvLogEvidence() (bool, string) {
	var parts []string
	// 1. gen2_status.txt (计划任务历史快照)
	if gs := hxcore.ReadGen2Status(); gs != "" {
		for _, ln := range strings.Split(gs, "\n") {
			t := strings.TrimSpace(ln)
			if strings.Contains(t, "Gen2") || strings.Contains(t, "无需操作") || strings.Contains(t, "ACHIEVED") {
				parts = append(parts, "计划任务历史: "+t)
				break
			}
		}
	}
	// 2. installer.log (安装/任务实跑日志) — 含驱动加载与 Gen2 达成铁证
	logPath := filepath.Join(os.TempDir(), "50HX_installer.log")
	if b, err := os.ReadFile(logPath); err == nil {
		s := string(b)
		if strings.Contains(s, "GEN2 ACHIEVED") || strings.Contains(s, "BAR0 校验通过") {
			parts = append(parts, "installer.log: 驱动曾成功加载并达成 Gen2")
		}
		if strings.Contains(s, "启动服务") && strings.Contains(s, "失败") {
			parts = append(parts, "installer.log: 曾出现驱动启动失败(可能杀软隔离/1072残留)")
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
	// v2.6.0: 版本标题写入 sb → 弹窗/diagnose.txt 都可见 (此前 fmt.Println 只进 log)
	w("==============================================\n")
	w("  CMP 50HX 解锁诊断  v3.0.0   %s\n", time.Now().Format("2006-01-02 15:04:05"))
	w("==============================================\n")
	gpuOK := hxcore.FindGPU()
	sbOn := hxcore.SecureBootOn()
	tsOn := hxcore.TestSigningOn()
	gsOn := hxcore.GspEnabled()
	sub, _, _ := hxcore.GspDiag() // 只需判断 GSP 键是否存在(开关式显示, 不展示寄存器/Adapter 细节)

	// --- A. 主判定: 算力 + Gen2 最优先 (v2.5) ---
	selfM, drvOK, drvFail := ensureDrivers()
	st := hxcore.ReadUnlockStateV2(6, 800)
	bar := strings.Repeat("=", 46)
	w("\n%s\n", bar)
	state := "无法实测 (驱动未就绪)"
	switch {
	case st.SS0OK && st.Unlocked && st.Speed >= 2:
		state = "算力满血 + Gen2 达成"
	case st.SS0OK && st.Unlocked && st.TLS >= 2:
		state = "算力满血 + Gen2 目标已配置 (当前链路未到 Gen2)"
	case st.SS0OK && st.Unlocked:
		state = "算力满血, Gen2 未达成"
	case st.SS0OK:
		state = "未解锁 (SS0 锁定)"
	}
	w("  解锁状态 : %s\n", state)
	comp := "不可读"
	if st.SS0OK {
		comp = fmt.Sprintf("%s (SS0=0x%08X SS1=0x%08X)",
			map[bool]string{true: "✓ 满血", false: "✗ 锁定"}[st.Unlocked], st.SS0, st.SS1)
	}
	spd := "不可读"
	if st.Speed >= 1 {
		names := map[uint32]string{1: "Gen1 (2.5 GT/s)", 2: "Gen2 (5.0 GT/s)", 3: "Gen3 (8.0 GT/s)", 4: "Gen4 (16 GT/s)"}
		spd = names[st.Speed]
		if spd == "" {
			spd = fmt.Sprintf("Gen%d", st.Speed)
		}
		if st.Width >= 1 {
			spd += fmt.Sprintf(" ×%d", st.Width)
		}
		if st.Speed < 2 && st.TLS >= 2 {
			spd += fmt.Sprintf(" (目标 Gen%d — 空闲省电降速属正常; 若持续负载仍 Gen1 见结论)", st.TLS)
		}
	}
	w("  算力     : %s\n", comp)
	w("  PCIe     : %s\n", spd)
	w("%s\n", bar)

	// --- B. 基础状态 ---
	gspTxt := "✗ 未启用(装 NVIDIA 驱动后由安装器自动设)"
	if gsOn {
		gspTxt = "✓ 已启用"
	} else if sub == "" {
		gspTxt = "— 未找到 GSP 键(需先装好 NVIDIA 驱动才能设置 GSP)"
	}
	w("GPU 40HX: %s   Secure Boot: %s   GSP: %s\n",
		map[bool]string{true: "✓", false: "✗"}[gpuOK],
		map[bool]string{true: "开启(需关闭!)", false: "关闭(OK)"}[sbOn], gspTxt)
	w("测试签名: %s  (v2.5 不需要, 建议关闭)\n",
		map[bool]string{true: "已开启", false: "关闭"}[tsOn])
	// v2.6.0: 引导模式 + 电源设置 — Legacy/MBR、快速启动、ASPM 是三类高频根因
	// (分别对应"EFI 装不上"/"关机再开 EFI 没跑"/"空闲 Gen1 误报失败")
	bootMode := "UEFI (OK)"
	if hxcore.FirmwareIsLegacy() {
		bootMode = "Legacy BIOS+MBR (无 EFI 分区, 算力解锁不可用!)"
	}
	fsOn := hxcore.FastStartupOn()
	ac, dc, aspmOK := hxcore.ASPMSavings()
	aspmStr := "不可检测(跳过)"
	if aspmOK {
		if ac == 0 && dc == 0 {
			aspmStr = "关闭(OK)"
		} else {
			aspmStr = fmt.Sprintf("开启(AC=%d DC=%d) — 空闲可能降速 Gen1, 建议关闭", ac, dc)
		}
	}
	w("引导模式: %s\n", bootMode)
	w("快速启动: %s   PCIe ASPM: %s\n",
		map[bool]string{true: "开启(建议关闭)", false: "关闭(OK)"}[fsOn],
		aspmStr)

	// --- C. 明细: Gen2 驱动(逐个)/任务/历史记录 ---
	// 逐个驱动显示: 可能一个被杀软拦了、另一个正常, 只显示汇总会误导。
	tsTxt := "✗ 未运行"
	if st.TSOK {
		tsTxt = "✓ 可用"
	} else if svcState(svcTS) == "RUNNING" {
		tsTxt = "⚠ 服务在, 但设备打不开"
	}
	wrTxt := "✗ 未运行"
	if st.WinRingOK {
		wrTxt = "✓ 可用"
	} else if svcState(svcWR) == "RUNNING" {
		wrTxt = "⚠ 服务在, 但设备打不开"
	}
	w("Gen2 驱动: ThrottleStop %s   WinRing0 %s\n", tsTxt, wrTxt)
	if selfM {
		w("  ↑ 由本诊断临时拉起, 测完即卸 — 不代表已安装\n")
	} else if st.TSOK || st.WinRingOK {
		w("  ↑ 驱动为已部署/外部加载\n")
	}
	if !drvOK && drvFail != "" {
		w("  └ 启动失败: %s\n", classifyLoadErr(drvFail))
	}
	w("\n")
	taskOK, taskStatus, taskResult := hxcore.TaskInfo(gen2TaskName)
	w("Gen2 任务: %s\n",
		map[bool]string{true: "已注册 (" + taskStatus + ", 上次结果: " + taskResult + ")",
			false: "未注册 (修复: 右键管理员运行 50HXInstaller.exe -task)"}[taskOK])
	// gen2_status.txt 是上次 Gen2 任务写入的"历史快照", 不是本次实测:
	// 只有驱动实测不可用时才作为参考展示, 且明确标注为历史记录,
	// 避免"卸载后还显示 ✅ Gen2"的误导。
	if !st.SS0OK || st.Speed < 2 {
		if gs := hxcore.ReadGen2Status(); gs != "" {
			w("  注: 存在上次 Gen2 任务的历史记录(非本次实测):\n%s\n", indentLines(gs))
			if !drvOK {
				w("       ↑ 驱动当前未运行 — 此为历史残留, 不代表当前状态\n")
			}
		}
	}
	if drvOK && !st.SS0OK {
		w("(驱动已运行但读不到算力寄存器 — 异常)\n")
	}

	// --- D. 结论与建议 ---
	verdict := ""
	switch {
	case st.Unlocked && st.Speed >= 2:
		verdict = ">>> 解锁成功: Tensor 满血 + Gen2"
		if st.Width >= 1 {
			verdict += fmt.Sprintf(" ×%d", st.Width)
		} else {
			verdict += " (链路宽度未测到)"
		}
	case st.Unlocked && st.TLS >= 2:
		if st.Speed == 1 {
			verdict = ">>> 算力满血 + Gen2 目标已配置 (当前 Gen1: 空闲省电降速或本次尚未训上; 负载/重训后回 Gen2)"
		} else {
			verdict = ">>> 算力满血 + Gen2 目标已配置 (当前链路速率未测到)"
		}
	case st.Unlocked:
		verdict = ">>> 算力满血; Gen2 未达成 — 登录任务每次登录已自动执行(含自动 Stage2); 仍失败可在 GUI ② 区点[立即执行 Gen2] 再试(详见 README §5.2)"
	case st.SS0OK:
		verdict = ">>> 本次开机未解锁 (SS0 锁定)"
		default:
			if !drvOK {
				if !isAdmin() {
					verdict = ">>> 驱动未加载: 本工具需管理员权限加载内核驱动以实测状态。请右键本程序 -> 以管理员身份运行"
				} else if gpuOK && gsOn {
					if ever, ev := drvLogEvidence(); ever {
						verdict = ">>> 驱动当前未运行, 但日志显示此前已成功达成 Gen2 (" + ev + ")。解锁已生效, 右键以管理员运行本工具可读实时状态"
					} else {
						verdict = ">>> 驱动不可用 — 请从 50HXUnlock 发布目录(含 gen2\\drivers)运行, 或先管理员重跑 50HXInstaller.exe 安装驱动"
					}
				} else {
					verdict = ">>> 无法完成解锁判定 (见上方分项)"
				}
			} else {
				verdict = ">>> 无法完成解锁判定 (见上方分项)"
			}
		}
	w("\n%s\n", verdict)
	if st.SS0OK && !st.Unlocked {
		if reason := hxcore.AnalyzeEfiLog(); reason != "" {
			w("%s\n", reason)
		}
	}

	// v2.6.0: 弹窗只显示"简洁结论 + 基础状态"; 下方详细建议/原始寄存器只进 diagnose.txt(日志)与剪贴板,
	// 不放 GUI —— 用户要求提示放 txt 不放弹窗, 社区看完整诊断去 logs 目录即可。
	guiHead := sb.String()

	if !gpuOK {
		tips = append(tips, "· 未检测到 40HX: 确认显卡已插且驱动已装")
	}
	if sbOn {
		tips = append(tips, "· Secure Boot 开启: 进 BIOS 关闭 (否则解锁 EFI 被拒)")
	}
	if tsOn {
		tips = append(tips, "· 测试签名已开启 (v2.5 不需要): bcdedit /set testsigning off 可关闭")
	}
	if !gsOn {
		tips = append(tips, "· GSP 未启用: 双击 50HXInstaller.exe → ① 勾 [GSP 启用] 点[安装所选组件]")
	}
	if gpuOK && st.SS0OK && !st.Unlocked {
		tips = append(tips, "· EFI 算力解锁未生效(SS0 锁定): 若本机未部署/已卸载 '50HX Unlock' 解锁 EFI, 此提示属预期, 算力会保持锁定 — 想恢复请重跑 50HXInstaller.exe 勾选[算力 EFI 部署+固件启动项]; 若 EFI 已装, 则确认开机走了 '50HX Unlock' 启动项 / Above 4G 已开 / Secure Boot 已关")
	}
	// v2.6.0: 社区高频根因的四条定向提示
	if hxcore.FirmwareIsLegacy() {
		tips = append(tips, "· 引导模式为 Legacy BIOS+MBR: 没有 EFI 分区, 算力解锁装不上 —\n  按README §2.4 用 mbr2gpt 转 GPT 后重跑安装器 (Gen2 不受影响)")
	}
	if fsOn {
		tips = append(tips, "· 快速启动(混合休眠)开启: 关机再开可能不做完整 UEFI 引导 → EFI 不执行;\n  安装器会自动关闭; 手动: 控制面板电源选项取消勾选『快速启动』")
	}
	if aspmOK && (ac > 0 || dc > 0) {
		tips = append(tips, "· PCIe 链路省电(ASPM)开启: 空闲时降到 Gen1 属正常省电, 负载自动回升;\n  想常驻 Gen2 可关闭: powercfg -setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0\n  (再加 -setdcvalueindex 同参数, 然后 -setactive SCHEME_CURRENT 生效)")
	}
	if !taskOK {
		tips = append(tips, "· Gen2 计划任务未注册: 登录后不会自动解锁 Gen2 —\n  双击 50HXInstaller.exe → ② 点[执行 Gen2 并安装自启]一步到位（本次解锁+注册自启）; 或 ① 勾[Gen2 登录自启]点[安装所选组件]")
	}
	if st.SS0OK && st.TLS < 2 && st.TLS >= 1 && st.Unlocked {
		tips = append(tips, "· Gen2 目标速率(TLS)仍是 Gen1: 解锁写入未生效 — 若日志显示 PL0 四寄存器全 OK 而回读 LNKCTL2 仍 Gen1,\n  多为驱动持链路策略毫秒内回写; 登录任务(前提: 已注册)在登录后会自动尝试并跑 Stage2 回退; 仍失败先在 GUI ② 点[立即执行 Gen2]（默认自动含 Stage2 回退）重试 — 仅当 ② 里关掉了自动回退或想强制触发时才用命令行 `50HXInstaller.exe -gen2 -hard`。已确认不是固件写保护, **不要刷 VBIOS** — 仍不行发诊断与 installer.log 反馈(见 README §5.2)")
	}
	if st.SS0OK && st.Unlocked && st.Speed < 2 && st.TLS >= 2 {
		tips = append(tips, "· Gen2 目标已配置(TLS=Gen2)但当前链路 Gen1: 多为空闲省电降速(正常, 负载自动回升); 若持续负载仍 Gen1: 直接在 GUI ② 点[立即执行 Gen2] 重训（Gen2AutoHard 默认开会自动走 Stage2 回退）; 仅当 ② 关掉自动回退或想强制触发时, 再用命令行 `50HXInstaller.exe -gen2 -hard`(瞬断链路, 见 README §3.3)")
	}
	if !taskOK && st.SS0OK && st.Unlocked && (st.Speed >= 2 || st.TLS >= 2) {
		tips = append(tips, "· 注: 当前 Gen2 状态来自 GPU 目标速率寄存器(TLS)实测; 若本次开机还没有任何解锁流程执行过(自启任务未注册), 该值多半是上次运行残留 — 完全关机再开/显卡复位后会回锁。请用 GUI ② [执行 Gen2 并安装自启] 一步到位(本次解锁+注册开机自启)")
	}
	if throttleStopAppRunning() && !drvOK {
		tips = append(tips, "· 检测到 ThrottleStop 软件在运行且本工具驱动未就绪: 本工具自动复用其驱动; 若仍失败, 关闭 ThrottleStop 后重跑安装器")
	}
	if !drvOK {
		if drvFail != "" {
			tips = append(tips, "· Gen2 驱动未能拉起: "+classifyLoadErr(drvFail))
		}
		if ever, ev := drvLogEvidence(); ever {
			tips = append(tips, "· 驱动当前未运行, 但日志显示此前已成功达成 Gen2 ("+ev+") — 解锁已生效, 右键以管理员运行本工具可读实时状态")
		} else {
			tips = append(tips, "· 驱动从未成功部署(无 installer.log/gen2_status 成功记录): 双击 50HXInstaller.exe → ① 区点[一键完整安装]完成部署与自启注册")
		}
	}
	if len(tips) > 0 {
		w("\n建议:\n%s\n", strings.Join(tips, "\n"))
	}
	// 弹窗只带第一条"下一步"(其余在 diagnose.txt/剪贴板) — 让安装者一眼知道该干嘛。
	popupTip := ""
	if len(tips) > 0 {
		popupTip = "\n\n▶ 下一步: " + strings.SplitN(tips[0], "\n", 2)[0]
	}

	// v2.6.0: 加强诊断快照 — 环境/驱动/原始 PCIe 寄存器/已知限制, 便于社区反馈
	w("\n========== 环境 ==========\n")
	w("  OS      : %s\n", osVersion())
	w("  管理员   : %s   工具版本: v3.0.0\n", map[bool]string{true: "是", false: "否"}[isAdmin()])
	w("\n========== 驱动 ==========\n")
	w("%s", driverDetail(svcTS, fileTS))
	w("%s", driverDetail(svcWR, fileWR))
	if selfM {
		w("  ↑ 本诊断【临时拉起】以读取硬件状态, 测完自动清理 — 不代表已安装\n")
	} else if st.TSOK || st.WinRingOK {
		w("  ↑ 驱动为已部署/外部加载, 本工具不清理\n")
	}
	w("  ThrottleStop 软件运行: %s\n", map[bool]string{true: "是(共存, 不删其驱动)", false: "否"}[throttleStopAppRunning()])
	w("\n========== 原始 PCIe 寄存器 (40HX) ==========\n")
	w("%s", rawPcieDump())
	w("%s", knownIssuesBlock())

	out := sb.String()
	fmt.Println(out)

	// v2.5: 本工具拉起过驱动则用完即卸 (保持系统无第三方驱动)
	if selfM {
		cleanupDrivers()
	}

	dir := collectLogs(out)
	copied := copyToClipboard(out)
	note := ""
	if copied {
		note = "\n\n完整诊断(含排查建议与原始寄存器)已复制到剪贴板 — 直接粘贴到 issue 即可。"
	}
	ok := st.Unlocked && (st.Speed >= 2 || st.TLS >= 2)
	// 弹窗只给简洁结论 + 指向详细日志; 详细内容已在 diagnose.txt 与剪贴板。
	msgbox(guiHead+popupTip+"\n\n完整诊断(含排查建议与原始 PCIe 寄存器)已写入:\n"+dir+"\\diagnose.txt\n排查引导见包内 AI辅助安装提示词.txt"+note,
		map[bool]uint{true: 0x40, false: 0x30}[ok])
}

func main() {
	if len(os.Args) < 2 || os.Args[1] != "-elevated" {
		if !isAdmin() {
			selfElevate()
			return
		}
	}
	// 输出镜像到统一日志目录
	dir := logsDir()
	if f, err := os.Create(filepath.Join(dir, "40HXCheck.log")); err == nil {
		os.Stdout = f
		os.Stderr = f
		fmt.Fprintf(f, "==== 40HXCheck %s ====\n", time.Now().Format("2006-01-02 15:04:05"))
	}
	check()
}
