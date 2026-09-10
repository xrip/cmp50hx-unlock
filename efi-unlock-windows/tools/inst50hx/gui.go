package main

// v2.6.0: 精简单界面 GUI (walk) — 无选项卡、无状态表格, 安装器只管安装。
// 打开时自动只读扫描一次(不展示明细): 结果只用于
//   ① 组件安装区的"环境提示"行(未检测到卡/SecureBoot/Legacy 等警告)
//   ② 缺失/未达标组件的自动预勾(已装不勾 = 不覆盖)
// 界面自上而下:
//   ① 组件安装 — [安装所选组件] / [一键完整安装(全流程)], 装完自动重扫更新提示
//   ② Gen2 策略 — 驱动运行策略 + 自动 Stage2 回退 + 失败重试次数/间隔,[保存策略]
//   ③ 操作日志 — AttachLogSink 实时输出(GUI 与 CLI 共用全部实现)
// 卸载与详细诊断不在本界面: 50HXUninstaller.exe / -uninstall / 50HXCheck.exe。
// 线程约定: OnClicked(UI 线程)只读控件 → goroutine 执行 → UI 变更一律经 sync()。

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

// ---- 环境扫描(只读; 结果喂 tip 与预勾选, 不展示明细表) ----

type statusItem struct {
	name string
	ok   bool
	note string
}

func scanStatus() []statusItem {
	items := []statusItem{}
	legacy := hxcore.FirmwareIsLegacy()
	items = append(items, statusItem{"引导模式", !legacy,
		map[bool]string{true: "UEFI (OK)", false: "Legacy+MBR — 算力解锁不可用, 需 mbr2gpt 转 GPT"}[legacy]})
	sbOn := hxcore.SecureBootOn()
	items = append(items, statusItem{"Secure Boot", !sbOn,
		map[bool]string{true: "开启(需关闭!)", false: "关闭 (OK)"}[sbOn]})
	gpuOK := hxcore.FindGPU()
	items = append(items, statusItem{"50HX 显卡", gpuOK,
		map[bool]string{true: "已检测到 (VEN_10DE&DEV_1E09)", false: "未检测到 — 确认插好且驱动已装"}[gpuOK]})
	gspOK := hxcore.GspEnabled()
	items = append(items, statusItem{"GSP (EnableGpuFirmware)", gspOK,
		map[bool]string{true: "已启用 (OK)", false: "未启用 — 解锁后可能 Code43 黑屏"}[gspOK]})

	espEFI := false
	if esp := hxcore.MountESP(); esp != "" {
		if _, err := os.Stat(esp + ":\\EFI\\50HX\\50HXUNLK.EFI"); err == nil {
			espEFI = true
		}
		hxcore.UnmountESP(esp)
	}
	items = append(items, statusItem{"ESP 解锁 EFI", espEFI,
		map[bool]string{true: "\\EFI\\50HX\\50HXUNLK.EFI 已部署", false: "未部署 (Legacy 机器属预期)"}[espEFI]})
	// 启动项三态(与安装器 verifyBootEntry 同口径): 首位 / 存在但不在首位 / 未创建
	bootOK := false
	bootNote := "未创建"
	if ex, first, ord := verifyBootEntry(); ex {
		if first {
			bootOK = true
			bootNote = "存在且 displayorder 首位"
		} else {
			bootNote = "存在但不在 displayorder 首位(当前顺序: " + ord + ") — 需进 BIOS 置顶"
		}
	}
	items = append(items, statusItem{"固件启动项", bootOK, bootNote})

	taskOK, taskStatus, taskResult := hxcore.TaskInfo(gen2TaskName)
	taskNote := "未注册 — Gen2 不会开机自动跑"
	if taskOK {
		taskNote = "状态 " + taskStatus + " 上次结果 " + taskResult
	}
	items = append(items, statusItem{"Gen2 登录任务", taskOK, taskNote})
	rkOK := runKeyPresent()
	items = append(items, statusItem{"Gen2 Run 键兜底", rkOK,
		map[bool]string{true: "已写入 (50HXGen2)", false: "未写入"}[rkOK]})

	// Gen2 驱动分层状态 — 判定见 hxcore/drvstate.go。
	// S0"用完即卸"/S1"看门狗"成功后 System32 文件与服务被自清理 → 缺失≠没装过。
	deps := hxcore.InspectGen2Drivers()
	if !hxcore.Gen2DriversDeployedOnce() {
		items = append(items, statusItem{"Gen2 驱动(从未部署)", false,
			"备份源/服务均无 — 下方勾选 [Gen2 驱动部署] 安装"})
	} else {
		var notes []string
		curOK := true
		cleanEnd := true
		for _, d := range deps {
			svcS := "服务未注册"
			if d.SvcReg {
				svcS = "服务 " + d.SvcStart
				if d.SvcStart == "DISABLED" {
					svcS += " ⚠被禁用(Gen2 拉不起, 重装修复)"
				}
				if d.SvcRunning {
					svcS += "/运行中"
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
			items = append(items, statusItem{"Gen2 驱动(用完即卸终态)", true,
				"曾部署; 已按策略自清理 — 下次登录任务会自动重部署(属正常)"})
		} else {
			items = append(items, statusItem{"Gen2 驱动部署状态", curOK, strings.Join(notes, " | ")})
		}
	}
	if exOK, err := hxcore.DefenderExclusionsPresent(); err != nil {
		items = append(items, statusItem{"Defender 排除", false,
			"查询失败(" + err.Error() + ") — 以管理员重扫或忽略"})
	} else {
		items = append(items, statusItem{"Defender 排除", exOK,
			map[bool]string{true: "两个 .sys + ProgramData 备份目录均已加白", false: "未加白 — 杀软可能误删驱动(重装补)"}[exOK]})
	}

	fsOn := hxcore.FastStartupOn()
	items = append(items, statusItem{"快速启动", !fsOn,
		map[bool]string{true: "开启(建议关闭 — EFI 可能不跑)", false: "关闭 (OK)"}[fsOn]})
	if ac, dc, aspmOK := hxcore.ASPMSavings(); aspmOK {
		off := ac == 0 && dc == 0
		items = append(items, statusItem{"PCIe ASPM", off,
			map[bool]string{true: "关闭 (OK)", false: fmt.Sprintf("开启(AC=%d DC=%d) — 空闲可能降速 Gen1", ac, dc)}[off]})
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

// ---- 日志面板写入器 (AttachLogSink 目标) ----

type guiLog struct {
	mw *walk.MainWindow
	te *walk.TextEdit
}

func (g *guiLog) Write(p []byte) (int, error) {
	s := string(p)
	if g.mw != nil && g.te != nil {
		// EDIT 控件换行需要 CRLF: 统一把 \n 规范成 \r\n, 否则日志会挤成一段
		s = strings.ReplaceAll(s, "\r\n", "\n")
		s = strings.ReplaceAll(s, "\r", "\n")
		s = strings.ReplaceAll(s, "\n", "\r\n")
		g.mw.Synchronize(func() { g.te.AppendText(s) })
	}
	return len(p), nil
}

// ---- GUI 状态 ----

type guiState struct {
	mw       *walk.MainWindow
	log      *guiLog
	teLog    *walk.TextEdit
	tip      *walk.Label
	busyBy   string // 当前占用互斥的操作名(""=空闲)。只在 UI 线程读写:
	// begin() 在 OnClicked(UI线程) 调用, end() 经 sync 回到 UI 线程 → 无线程竞争。
	lastScan  []statusItem
	lastGuide string // 上次打印的环境指引(变化才打印, 防重扫刷屏)
	lastAV      string // 上次识别到的第三方杀软(同上)
	lastDefWarn string // "无 Defender 模块"提示去重

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

// begin: 在 UI 线程(OnClicked)同步抢全局互斥 — 一次只允许一个长操作在跑。
// 抢到即占住(busyBy)并同步禁用按钮, 杜绝"连点/快速双击"在 goroutine 里抢锁的竞态。
func (st *guiState) begin(what string) bool {
	if st.busyBy != "" {
		fmt.Println("[!] 正在执行 " + st.busyBy + " — " + what + " 已跳过, 请等它完成后再试")
		return false
	}
	st.busyBy = what
	return true
}

func (st *guiState) end() {
	st.sync(func() { st.busyBy = "" })
}

// setActionsEnabled: 初始自动扫描期间禁用执行按钮, 防止与手动操作并发抢 IO。
func (st *guiState) setActionsEnabled(on bool) {
	st.sync(func() {
		for _, b := range []*walk.PushButton{st.pbInstall, st.pbFull, st.pbSave, st.pbGen2} {
			if b != nil {
				b.SetEnabled(on)
			}
		}
	})
}

// summaryText: 把"不处理就装不上/装了也不生效"的最关键状态合成安装区顶部提示。
func (st *guiState) summaryText(items []statusItem) string {
	m := map[string]statusItem{}
	for _, it := range items {
		m[it.name] = it
	}
	if it, ok := m["50HX 显卡"]; ok && !it.ok {
		return "⚠ 未检测到 50HX — 请先确认显卡插好且驱动已装, 否则安装无意义"
	}
	var warns []string
	if it, ok := m["Secure Boot"]; ok && !it.ok {
		warns = append(warns, "Secure Boot 开启, 需进 BIOS 关闭")
	}
	if it, ok := m["引导模式"]; ok && !it.ok {
		warns = append(warns, "Legacy+MBR 引导, 算力 EFI 装不上(需 mbr2gpt 转 GPT)")
	}
	if it, ok := m["Gen2 驱动(从未部署)"]; ok && !it.ok {
		warns = append(warns, "Gen2 驱动从未部署")
	}
	if it, ok := m["Gen2 登录任务"]; ok && !it.ok {
		warns = append(warns, "Gen2 登录自启未注册")
	}
	// 启动项: 仅 UEFI 下检查(存在但不在首位 / 未创建)
	if it, ok := m["固件启动项"]; ok && !it.ok {
		if bl, ok2 := m["引导模式"]; !ok2 || bl.ok {
			if strings.Contains(it.note, "不在") {
				warns = append(warns, "启动项存在但不在首位, 需 BIOS 置顶")
			} else {
				warns = append(warns, "固件启动项未创建")
			}
		}
	}
	if len(warns) == 0 {
		return "✓ 环境就绪 — 缺失组件已自动预勾, 点[安装所选组件]或[一键完整安装]即可"
	}
	s := "⚠ " + strings.Join(warns, "; ")
	if r := []rune(s); len(r) > 90 {
		s = string(r[:90]) + "…"
	}
	return s
}

// envGuide: "已知问题 → 解决步骤"的安装指引(参照 v2.4 弹窗文案的引导风格,
// 只输出当前确实存在的问题对应的处理步骤, 供日志阅读)。
func (st *guiState) envGuide(items []statusItem) string {
	m := map[string]statusItem{}
	for _, it := range items {
		m[it.name] = it
	}
	var g []string
	if it, ok := m["50HX 显卡"]; ok && !it.ok {
		g = append(g, "· 未检测到 40HX: ①确认供电与 PCIe 插稳; ②设备管理器看是否有 code43(未装驱动先装); ③BIOS 关 CSM(纯 UEFI)后再扫")
	}
	if it, ok := m["Secure Boot"]; ok && !it.ok {
		g = append(g, "· Secure Boot 开启: 重启按 Del/F2 进 BIOS → Security/Boot → Secure Boot=Disabled → F10 保存 → 回系统重跑本工具")
	}
	if it, ok := m["引导模式"]; ok && !it.ok {
		g = append(g, "· Legacy+MBR 引导: 无 EFI 分区算力解锁装不上 → 管理员 CMD 依次: mbr2gpt /validate /allowfullos → mbr2gpt /convert /allowfullos → 重启改 UEFI(关 CSM) → 重跑本工具(完整步骤见 README §2.4)")
	}
	if it, ok := m["固件启动项"]; ok && !it.ok {
		if bl, ok2 := m["引导模式"]; !ok2 || bl.ok {
			if strings.Contains(it.note, "不在") {
				g = append(g, "· 启动项存在但不在 displayorder 首位: 进 BIOS 把 '50HX Unlock' 设为第一启动项(否则开机可能不执行)")
			} else {
				g = append(g, "· 固件启动项未创建: 勾选上方[算力 EFI 部署 + 固件启动项]即可自动创建并置顶; 若 BIOS 列表仍不显示, 用 PE(firPE)/DiskGenius 修复引导或手动把 UEFI 盘设为首启(走 bootx64 兜底)")
			}
		}
	}
	if it, ok := m["Gen2 驱动(从未部署)"]; ok && !it.ok {
		g = append(g, "· Gen2 驱动从未部署: 勾选[Gen2 驱动部署 + Defender 排除]安装(会自动加白并处理第三方杀软信任提示)")
	}
	if it, ok := m["Gen2 登录任务"]; ok && !it.ok {
		g = append(g, "· Gen2 登录自启未注册: 勾选[Gen2 登录自启]安装; 或管理员运行 50HXInstaller.exe -task")
	}
	if it, ok := m["ESP 解锁 EFI"]; ok && !it.ok {
		if bl, ok2 := m["引导模式"]; !ok2 || bl.ok {
			g = append(g, "· 算力解锁 EFI 未部署(若你是刚卸载/暂不装算力: 属预期 — 算力锁不会自动解, Gen2 不受影响; 想恢复算力解锁就勾上方 [算力 EFI 部署 + 固件启动项] 安装)")
		}
	}
	return strings.Join(g, "\n")
}

// scanOnce: 只读扫描一次并刷新顶部提示(不展示明细)。
// 同时输出: 环境处理指引(已知问题→解决步骤)与第三方杀软报告 — 仅在内容变化时打印。
func (st *guiState) scanOnce() {
	items := scanStatus()
	st.lastScan = items
	tip := st.summaryText(items)
	st.sync(func() {
		if st.tip != nil {
			st.tip.SetText(tip)
		}
	})
	// 第三方杀软探测(只读): 它不读 Defender 排除列表, 需手动放行
	av := hxcore.DetectThirdPartyAV()
	avKey := strings.Join(av, ",")
	if avKey != st.lastAV {
		if len(av) > 0 {
			fmt.Println("[杀软] 检测到第三方安全软件: " + strings.Join(av, " / ") +
				" — 请在信任/白名单放行 4 个驱动路径:")
			fmt.Println("        C:\\Windows\\System32\\drivers\\ThrottleStop.sys")
			fmt.Println("        C:\\Windows\\System32\\drivers\\WinRing0x64.sys")
			fmt.Println("        %ProgramData%\\50HXUnlock\\drivers\\ 下的 ThrottleStop.sys / WinRing0x64.sys")
		}
		st.lastAV = avKey
	}
}

// applySmartDefaults: 按最近一次扫描预勾选 — 组件缺失/未达标才勾(已装不勾=不覆盖)。
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
	if !flags["50HX 显卡"] {
		fmt.Println("[i] 未检测到 50HX — 安装区保持全不勾(请先确认显卡/驱动)")
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
	// 驱动部署需要与否不能只看 System32 文件(用完即卸终态会缺失):
	// 从未部署 / 服务被 DISABLED / 文件 0字节或与备份不一致 → 才需要装
	needDrv := hxcore.Gen2DriversNeedDeploy()
	needEfi := false
	if flags["引导模式"] {
		needEfi = !flags["ESP 解锁 EFI"] || !flags["固件启动项"]
	} else {
		fmt.Println("[i] Legacy+MBR 引导: 算力 EFI 不可装 — 未预勾(需先 mbr2gpt 转 GPT)")
	}
	needTask := !flags["Gen2 登录任务"]
	needFast := !flags["快速启动"]
	needAspm := !aspmOK
	needPerf := !hxcore.HighPerfPlanActive()
	// Defender 实时防护: 开着→预勾(如实); 已关→不勾; 模块缺失/查不到→不勾+简短提示一次
	needDefOff, defKnown := false, false
	if on, err := hxcore.DefenderRealtimeProtectionOn(); err == nil {
		defKnown = true
		needDefOff = on
	} else {
		defWarn := "本机无 Defender 管理模块(第三方杀软请在其信任列表放行驱动)"
		if !errors.Is(err, hxcore.ErrMpUnavailable) {
			defWarn = "Defender 状态查询失败: " + err.Error()
		}
		if defWarn != st.lastDefWarn {
			fmt.Println("[i] " + defWarn)
			st.lastDefWarn = defWarn
		}
	}
	var pre []string
	st.sync(func() {
		// 显式双向设置: 缺失/未达标 → 勾(待执行); 已就绪 → 取消勾(不覆盖)。
		// v3.0.0 修复: 旧实现只 SetChecked(true), 装完重扫后已就绪项仍保持勾选。
		st.ckGsp.SetChecked(needGsp)
		if needGsp {
			pre = append(pre, "GSP")
		}
		st.ckDrv.SetChecked(needDrv)
		if needDrv {
			pre = append(pre, "Gen2 驱动")
		}
		st.ckEfi.SetChecked(needEfi)
		if needEfi {
			pre = append(pre, "算力 EFI+启动项")
		}
		st.ckTask.SetChecked(needTask)
		if needTask {
			pre = append(pre, "Gen2 登录自启")
		}
		st.ckFast.SetChecked(needFast)
		if needFast {
			pre = append(pre, "关快速启动")
		}
		st.ckAspm.SetChecked(needAspm)
		if needAspm {
			pre = append(pre, "关ASPM")
		}
		st.ckPerf.SetChecked(needPerf)
		if needPerf {
			pre = append(pre, "高性能计划")
		}
		wantDefOff := defKnown && needDefOff
		st.ckDefOff.SetChecked(wantDefOff)
		if wantDefOff {
			pre = append(pre, "关 Defender 实时防护")
		}
		// 勾选与否由上面扫描判定; 状态与信任/白名单说明只进日志, 不上 UI 标签
	})
	if len(pre) > 0 {
		fmt.Println("[i] 预勾: " + strings.Join(pre, " / ") + " → 点[安装所选组件]执行; 其余已就绪不勾(不覆盖)")
		return
	}
	// 全都没勾: 一行列出原因(均已就绪, 勾了会覆盖/刷新)
	var ready []string
	if !needGsp {
		ready = append(ready, "GSP 已启用")
	}
	if !needDrv {
		ready = append(ready, "Gen2 驱动已就绪")
	}
	if !flags["引导模式"] {
		ready = append(ready, "算力 EFI(先 mbr2gpt)")
	} else if !needEfi {
		ready = append(ready, "EFI+启动项已就绪")
	}
	if !needTask {
		ready = append(ready, "自启已注册")
	}
	if !needFast {
		ready = append(ready, "快速启动已关")
	}
	if !needAspm {
		ready = append(ready, "ASPM 已关")
	}
	if !needPerf {
		ready = append(ready, "已是高性能计划")
	}
	if defKnown && !needDefOff {
		ready = append(ready, "Defender 实时防护已关")
	}
	fmt.Println("[i] 均已就绪, 未勾选(不覆盖): " + strings.Join(ready, " | "))
}

// printDefErr: Defender 相关错误的简短呈现 — 模块缺失给固定短句+放行路径, 其余原样输出。
func (st *guiState) printDefErr(prefix string, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, hxcore.ErrMpUnavailable) {
		fmt.Println(prefix + "本机无 Defender 管理模块 — 自动加白/实时防护开关不可用")
		fmt.Println(prefix + "第三方杀软请在其信任/白名单放行:")
		fmt.Println("      C:\\Windows\\System32\\drivers\\ThrottleStop.sys / WinRing0x64.sys")
		fmt.Println("      %ProgramData%\\50HXUnlock\\drivers\\ 下同名两个 .sys")
		return
	}
	fmt.Println(prefix + err.Error())
}

// loadPolicyUI: 启动时回读当前策略(须在 UI 线程调用 — Create 之后、Run 之前)
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

// savePolicy: Gen2 策略落盘 (HKLM\SOFTWARE\50HXUnlock, -gen2 登录任务读取)
func (st *guiState) savePolicy() {
	defer st.end()
	strat := 0
	for i, rb := range st.rbStrategy {
		if rb.Checked() {
			strat = i
		}
	}
	if err := hxcore.SetConfigInt("DriverStrategy", strat); err != nil {
		fmt.Println("[策略] 保存失败:", err)
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
	fmt.Printf("[策略] 已保存: 驱动策略=%d Gen2AutoHard=%d 重试=%d次/间隔=%d分钟 (登录任务/-gen2 生效)\n", strat, auto, cnt, interval)
	if strat == hxcore.DriverStrategyResident {
		if ok, _, _ := hxcore.TaskInfo(gen2TaskName); !ok {
			fmt.Println("[提示] 常驻守护需登录自启任务承载: 请在 ① 区勾[Gen2 登录自启]点[安装所选组件], 或用 ② [执行 Gen2 并安装自启] 一步到位")
		} else {
			fmt.Println("[提示] 已选常驻守护: 请再点一次 ② [执行 Gen2 并安装自启](或 ① [Gen2 登录自启])刷新任务命令行, 使其携带守护参数(-guard)")
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
		Title:    "CMP 50HX 解锁管理器 v3.0.0",
		MinSize:  Size{Width: 780, Height: 660},
		Size:     Size{Width: 860, Height: 800},
		Layout:   VBox{Spacing: 6},
		Children: []Widget{
			GroupBox{
				Title:  "① 组件安装与环境设置 (按当前状态预勾选; 勾选 = 执行/刷新)",
				Layout: VBox{Spacing: 4},
				Children: []Widget{
					Label{AssignTo: &st.tip, Text: "正在扫描环境…"},
					Composite{
						Layout: Grid{Columns: 2},
						Children: []Widget{
							CheckBox{AssignTo: &st.ckGsp, Text: "GSP 启用 (EnableGpuFirmware=1)"},
							CheckBox{AssignTo: &st.ckEfi, Text: "算力 EFI + 固件启动项"},
							CheckBox{AssignTo: &st.ckDrv, Text: "Gen2 驱动部署 + Defender 排除"},
							CheckBox{AssignTo: &st.ckTask, Text: "Gen2 登录自启"},
							CheckBox{AssignTo: &st.ckFast, Text: "电源: 关闭快速启动"},
							CheckBox{AssignTo: &st.ckAspm, Text: "电源: 关闭 PCIe 链路省电"},
							CheckBox{AssignTo: &st.ckPerf, Text: "电源: 高性能电源计划"},
							CheckBox{AssignTo: &st.ckDefOff, Text: "关闭 Defender 实时防护"},
						},
					},
					Composite{
						Layout: HBox{},
						Children: []Widget{
							PushButton{AssignTo: &st.pbInstall, Text: "安装所选组件", OnClicked: func() {
								// begin 在 UI 线程同步抢锁: 抢到即占住, 连点到不了这里
								if !st.begin("组件安装") {
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
							PushButton{AssignTo: &st.pbFull, Text: "一键完整安装 (全流程)", OnClicked: func() {
								if !st.begin("完整安装") {
									return
								}
								go func() {
									defer st.end()
									st.sync(func() { st.pbFull.SetEnabled(false) })
									defer st.sync(func() { st.pbFull.SetEnabled(true) })
									install()
									st.scanOnce() // 装完自动重扫, 顶部提示/预勾随之更新
									st.applySmartDefaults()
								}()
							}},
						},
					},
				},
			},
			GroupBox{
				Title:  "② Gen2 策略 (保存即生效; 登录任务与 -gen2 读取, 详见 README §2.5)",
				Layout: VBox{Spacing: 4},
				Children: []Widget{
					Label{Text: "驱动策略: Gen2 解锁用的两个驱动, 跑完后怎么处理"},
					Label{Text: "① 用完即卸(默认, 每次自动清理, 游戏/反作弊最干净)   ② 失败自动重试   ③ 常驻守护(驱动保留, 每分钟自查 Gen2, TLS 丢失自动重训)"},
					Composite{
						Layout: Grid{Columns: 3},
						Children: []Widget{
							RadioButton{AssignTo: &st.rbStrategy[0], Text: "用完即卸 (默认/推荐)"},
							RadioButton{AssignTo: &st.rbStrategy[1], Text: "失败自动重试"},
							RadioButton{AssignTo: &st.rbStrategy[2], Text: "常驻守护 (定时看 Gen2)"},
						},
					},
					CheckBox{AssignTo: &st.ckAutoHard, Text: "Gen2 未达成时自动执行 Stage2 回退 (Link Disable + PnP 恢复; 关掉可避免唯一显示卡登录后瞬断数秒)"},
					Composite{
						Layout: HBox{},
						Children: []Widget{
							Label{Text: "失败自动重试:"},
							NumberEdit{AssignTo: &st.neRetryCnt, MinValue: 0.0, MaxValue: 12.0, MinSize: Size{Width: 56}},
							Label{Text: "次 / 间隔:"},
							NumberEdit{AssignTo: &st.neRetryMin, MinValue: 1.0, MaxValue: 240.0, MinSize: Size{Width: 56}},
							Label{Text: "分钟"},
						},
					},
					Composite{
						Layout: HBox{},
						Children: []Widget{
							PushButton{AssignTo: &st.pbSave, Text: "保存策略", OnClicked: func() {
								if !st.begin("保存策略") {
									return
								}
								go st.savePolicy()
							}},
							PushButton{AssignTo: &st.pbGen2, Text: "立即执行 Gen2 (仅本次解锁)", OnClicked: func() {
								if !st.begin("立即执行 Gen2") {
									return
								}
								go func() {
									defer st.end()
									st.sync(func() { st.pbGen2.SetEnabled(false) })
									defer st.sync(func() { st.pbGen2.SetEnabled(true) })
									fmt.Println("[Gen2] 立即执行一次(等价命令行 -gen2): 临时加载驱动→解锁→默认用完即卸。")
									fmt.Println("[Gen2] 注意: 本按钮【仅本次生效】, 不会安装开机自启;")
									fmt.Println("[Gen2] 想装好后每次开机自动解锁, 请点右侧[执行 Gen2 并安装自启], 或勾①区 [Gen2 登录自启] 并安装。")
									gen2Main()
									if hxcore.DriverStrategy() == hxcore.DriverStrategyResident {
										fmt.Println("[提示] 已选'常驻守护': 本次已解锁; 每分钟自查由登录自启任务承担(下次登录起), 未注册自启则守护不会运行。")
									}
									st.scanOnce() // Gen2 后驱动/终态可能变化, 更新提示
								}()
							}},
							PushButton{AssignTo: &st.pbGen2Install, Text: "执行 Gen2 并安装自启 (本次+开机自动)", OnClicked: func() {
								if !st.begin("解锁并安装自启") {
									return
								}
								go func() {
									defer st.end()
									st.sync(func() { st.pbGen2Install.SetEnabled(false) })
									defer st.sync(func() { st.pbGen2Install.SetEnabled(true) })
									fmt.Println("== 执行 Gen2 并安装自启 ==")
									fmt.Println("[Gen2] 步骤1/2: 先解锁本次(临时加载驱动→解锁→默认用完即卸)...")
									gen2Main()
									fmt.Println("[Gen2] 步骤2/2: 安装开机自启 — 驱动部署+Defender 加白 + 登录任务 + Run 键...")
									installDrivers()
									if err := hxcore.AddDefenderExclusions(); err != nil {
										st.printDefErr("  [Defender] ", err)
									} else {
										fmt.Println("  [Defender] 驱动文件/备份目录已加白")
									}
									setRunKey()
									if err := setupGen2Task(); err != nil {
										fmt.Println("  [!] 登录自启注册失败:", err)
										fmt.Println("  [!] 可稍后在 ① 区勾 [Gen2 登录自启] 点[安装所选组件] 补装")
									} else {
										fmt.Println("  [自启] 注册完成 — 下次登录会自动解锁 Gen2(本次已先解锁, 无需重启)")
										if hxcore.DriverStrategy() == hxcore.DriverStrategyResident {
											fmt.Println("  [自启] 常驻守护已启用: 登录任务将每分钟自查 Gen2, TLS 丢失自动重训")
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
				Title:  "③ 操作日志 (实时)",
				Layout: VBox{},
				Children: []Widget{
					TextEdit{AssignTo: &st.teLog, ReadOnly: true, VScroll: true,
						MinSize: Size{Height: 120}, StretchFactor: 2},
				},
			},
		},
	}.Create()
	if createErr != nil {
		msgbox("50HX 安装器", "GUI 初始化失败: "+createErr.Error()+"\n请使用命令行方式 (50HXInstaller.exe -h)。", mbIconError)
		return
	}
	st.log.mw = st.mw
	st.log.te = st.teLog
	AttachLogSink(st.log)

	st.loadPolicyUI() // Gen2 策略回读(UI 线程, Run 之前)

	fmt.Println("CMP 50HX 解锁管理器 v3.0.0 已启动(管理员)。")
	go func() {
		// 打开自动扫描一次: 预勾选 + 顶部提示; 期间禁用执行按钮防并发。
		// 结果由 applySmartDefaults 打印([i] 已预勾… / [i] 组件均已就绪…)。
		st.setActionsEnabled(false)
		defer st.setActionsEnabled(true)
		st.scanOnce()
		st.applySmartDefaults()
	}()
	st.mw.Run()
}

// installSelected: 安装所选组件与设置(顺序执行, 输出全部进日志面板)。
// 分段风格同 CLI 全流程; 不再出现孤立的 [x/8] 编号(那是 install() 的编排编号)。
func (st *guiState) installSelected(sel map[string]bool) {
	defer st.end()
	st.sync(func() { st.pbInstall.SetEnabled(false) })
	defer st.sync(func() { st.pbInstall.SetEnabled(true) })
	nameOf := map[string]string{
		"gsp": "GSP 启用", "drv": "Gen2 驱动部署", "efi": "算力 EFI + 启动项",
		"task": "Gen2 登录自启", "fast": "关闭快速启动", "aspm": "关闭 ASPM",
		"perf": "高性能电源计划", "defoff": "关闭 Defender 实时防护",
	}
	var parts []string
	for _, k := range []string{"gsp", "drv", "efi", "task", "fast", "aspm", "perf", "defoff"} {
		if sel[k] {
			parts = append(parts, nameOf[k])
		}
	}
	if len(parts) == 0 {
		fmt.Println("[i] 未勾选任何组件/设置 — 请先勾选再点[安装所选组件]")
		return
	}
	fmt.Println("== 执行: " + strings.Join(parts, " / ") + " ==")
	if sel["gsp"] {
		fmt.Println("──── GSP 启用 (EnableGpuFirmware=1, 解锁不黑屏的关键) ────")
		if err := enableGsp(); err != nil {
			fmt.Println("  [GSP] 失败:", err)
		} else {
			fmt.Println("  [GSP] EnableGpuFirmware=1 已设置 (重启后 GSP-RM 生效)")
		}
	}
	if sel["drv"] {
		fmt.Println("──── Gen2 驱动部署 + Defender 排除 (ThrottleStop/WinRing0) ────")
		installDrivers()
		if err := hxcore.AddDefenderExclusions(); err != nil {
			st.printDefErr("  [Defender] ", err)
		} else {
			fmt.Println("  [Defender] 驱动文件/备份目录已加白")
		}
	}
	if sel["efi"] {
		fmt.Println("──── 算力 EFI 部署 + 固件启动项 (双路写入 + 置顶) ────")
		installEFI()
	}
	if sel["task"] {
		fmt.Println("──── Gen2 登录自启 (SYSTEM 任务 + Run 键兜底) ────")
		setRunKey()
		if err := setupGen2Task(); err != nil {
			fmt.Println("  [!] 登录自启注册失败:", err)
			fmt.Println("  [!] 可稍后以管理员运行: 50HXInstaller.exe -task")
		}
	}
	if sel["fast"] || sel["aspm"] || sel["perf"] {
		fmt.Println("──── 电源设置 (细项; 均可在系统电源选项中改回) ────")
	}
	if sel["fast"] {
		if hxcore.FastStartupOn() {
			if err := hxcore.SetFastStartupOff(); err != nil {
				fmt.Println("  [电源] 关闭快速启动失败:", err)
			} else {
				fmt.Println("  [电源] 快速启动已关闭 (HiberbootEnabled=0)")
			}
		} else {
			fmt.Println("  [电源] 快速启动: 原本已关(OK)")
		}
	}
	if sel["aspm"] {
		if ac, dc, ok := hxcore.ASPMSavings(); !ok {
			fmt.Println("  [电源] PCIe ASPM: 本机未公开该设置, 跳过")
		} else if ac == 0 && dc == 0 {
			fmt.Println("  [电源] PCIe ASPM: 原本已关(OK)")
		} else {
			if err := hxcore.SetASPMOff(); err != nil {
				fmt.Println("  [电源] ASPM 关闭失败:", err)
			} else {
				fmt.Printf("  [电源] PCIe ASPM 已关闭(原 AC=%d/DC=%d)\n", ac, dc)
			}
		}
	}
	if sel["perf"] {
		if hxcore.HighPerfPlanActive() {
			fmt.Println("  [电源] 电源计划: 已是高性能(OK)")
		} else if err := hxcore.SetHighPerfPlan(); err != nil {
			fmt.Println("  [电源] 切换高性能计划失败:", err)
		} else {
			fmt.Println("  [电源] 已切换到高性能电源计划 (可在电源选项改回)")
		}
	}
	if sel["defoff"] {
		fmt.Println("──── Windows Defender 实时防护 ────")
		on, err := hxcore.DefenderRealtimeProtectionOn()
		if err != nil {
			st.printDefErr("  [!] ", err)
		} else if !on {
			fmt.Println("  [Defender] 实时防护当前已关闭(无需操作)")
		} else if err := hxcore.SetDefenderRealtimeProtection(false); err != nil {
			st.printDefErr("  [!] ", err)
			if !errors.Is(err, hxcore.ErrMpUnavailable) {
				fmt.Println("  [!] 常见原因: Windows 安全中心开了'篡改防护' — 请先关闭它再重试")
			}
		} else {
			fmt.Println("  [Defender] 实时防护已关闭")
			fmt.Println("  [Defender] 恢复: 管理员 PowerShell 运行 Set-MpPreference -DisableRealtimeMonitoring $False")
		}
	}
	fmt.Println("== 执行完成, 自动重扫状态 ==")
	st.scanOnce()
	st.applySmartDefaults()
}
