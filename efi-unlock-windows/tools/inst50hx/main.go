// 50HX 一键安装工具 v3.0.0 (CMP 50HX Windows Unlock Installer)
// 功能:
//
//	(默认) 安装: GSP 启用(EnableGpuFirmware=1) + ESP 双路部署 50HXUNLK.EFI (V70)
//	      + BootOrder 置顶 + 驱动 + Gen2 自启动
//	-gen2        立即执行 Gen2 解锁(供登录自启动调用, 幂等)
//	-uninstall   卸载(移除启动项/Run键/驱动服务/EnableGpuFirmware)
//	-status      状态检查
//
// 资源 embed (v2.5): 50HXUNLK.EFI (V70 解锁版) / ThrottleStop.sys / WinRing0x64.sys
// v2.6.0 关键修复(社区 #2/#5/#6/#7 + v2.4.5 时代排障结论):
//  1. EFI 部署失败不再中止安装 — Legacy/MBR(无 ESP)只跳过 EFI 两步, Gen2 任务
//     照常注册(此前 [5/8] 直接 return, 是"装了驱动开机却不跑 Gen2"的统一根因)
//  2. 引导模式检测(GetFirmwareType): Legacy → 弹窗给 mbr2gpt 无损转换完整指引
//  3. 计划任务创建后 schtasks query 二次校验 + 重试; -task 失败以非零码退出
//     (命令行调用时的 errorlevel 检查从死代码变为有效)
//  4. 自动关闭快速启动(混合休眠)与 PCIe 链路省电(ASPM) — 前者避免"关机再开
//     不走完整 UEFI 引导", 后者减少空闲降到 Gen1 被误读为解锁失败
//  5. Gen2 核心增强: LNKCTL2 读改写(不清高位) + root/GPU 交替重训最多 4 轮 +
//     以 TLS 目标速率判成败(空闲省电降速 Gen1 不再误报失败)
// v2.6.0 关键加固(自启动通道设计与并发安全, 回应"多自启动路径怕出问题"):
//  1. Gen2 单实例内核互斥体(Global\50HXGen2SingleInstance): SYSTEM 任务 / Run 键 /
//     手动 -gen2 即使并发触发, 也仅一个进程进入"加载-卸载 BYOVD 驱动 + 抢 BAR0"
//     临界区, 杜绝双进程争用驱动服务名与链路寄存器导致的状态错乱
//  2. 自启动通道收敛为"两路互斥串行": Run 键登录瞬间先试(可能 GPU 未就绪而失败,
//     静默交权), SYSTEM 任务延迟 30s 再确认; 其余 13 类路径(HKCU/HKLM Run 之外)
//     均运行于用户态、无法 sc start 内核驱动, 故不采用(详见设计文档)
//  3. 定位 50HX 失败重试最多 3 次(间隔 2s), 容忍慢速 GPU 初始化导致的假失败
// v2.4 关键变更(社区兼容):
//  1. embed EFI 回到 V70 原版 (793d765e, 用户实测解锁成功) — v2.1/v2.2 精简版失败教训
//  2. ESP 双路部署: \EFI\50HX\50HXUNLK.EFI (BCD 主路径)
//     + \EFI\Boot\bootx64.efi (UEFI 标准 fallback, 原文件备份 .50hx.bak)
//     解决部分主板不认非标准 EFI 路径/忽略 BCD displayorder 导致"装完重启没反应"
//  3. BootOrder 写入后从固件读回验证, 不在首位时明确弹窗提示 BIOS 手动置顶
//  4. 关键 BIOS 操作全部进消息框 (社区用户不看 README/日志)
//
// v2.3 关键: EnableGpuFirmware=1 启用 GSP — 50HX 默认 GSP 关(CPU-RM 模式)时,
//
//	EFI 解锁后 nvlddmkm 拒绝 SEC2 状态 -> Code43 黑屏; GSP-RM 模式能接受解锁.
package main

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"50hxcore"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

//go:embed embed/*
var embedded embed.FS

const (
	gpuVenDev = "VEN_10DE&DEV_1E09"
	efiDir    = "\\EFI\\50HX"
	efiFile   = "50HXUNLK.EFI"
	bootDesc  = "50HX Unlock"
	// v2.4: UEFI 标准回退路径 (固件 BootOrder 全部无效/未签名时自动尝试此路径;
	// 解决部分主板忽略 BCD displayorder / 不认非标准 \EFI\50HX 目录)
	efiStdDir = "\\EFI\\Boot"
	efiStdF   = "bootx64.efi"
	efiBakExt = ".50hx.bak" // bootx64.efi.50hx.bak 原文件备份
	// v2.3: GSP 启用注册表 (EnableGpuFirmware=1) — 解锁不黑屏的关键!
	// 50HX 的显示适配器 Class 子键 (0001 = 40HX; 多卡时需按 AdapterString 找)
	gpuClassPath  = `SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}`
	gpuClassGUID  = `{4d36e968-e325-11ce-bfc1-08002be10318}` // Driver 值反查用
	gpuEnableFw   = "EnableGpuFirmware"
	gpuAdapterStr = "HardwareInformation.AdapterString"
	gpuAdapter40  = "CMP 50HX"
	// v2.4.6: Gen2 的 SYSTEM 计划任务名(卸载时按名字删除)
	gen2TaskName = "50HX PCIe Gen2 Bring-up"
	// v2.6.0: Gen2 失败后的自动重试任务(一次性, 成功即删, 卸载链按名清理)
	gen2RetryTask = "50HXGen2Retry"
)

func main() {
	// GUI 无窗口版(v1.1): 输出全部镜像到日志(默认 %TEMP%\50HX_installer.log, 可 -log 指定)
	setupLog("50HX_installer.log")
	// v2.6.0: 双击(无参数)或 UAC 提权重启(-elevated)默认进入 GUI 管理界面;
	// 命令行参数(-gen2/-task/-uninstall/-status/-silent/-hard)语义保持不变。
	if len(os.Args) <= 1 || (len(os.Args) == 2 && os.Args[1] == "-elevated") {
		runGUI()
		return
	}
	// install/-uninstall 需管理员: 非提升时自动 ShellExecute runas 弹 UAC 重启
	needAdmin := true
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-gen2", "-gspensure", "-status", "-h", "-help", "--help":
			needAdmin = false
		}
		// -task 需管理员(GUI 双击自动 UAC; gen2/status 等只读或 SYSTEM 任务调用无需)
		if os.Args[1] == "-task" {
			needAdmin = true
		}
	}
	if needAdmin && !isAdmin() {
		if hasArg("-elevated") {
			// 已提权过一次仍失败(如静默提权策略下受限token) -> 禁止再循环, 直接报错
			msgbox("50HX 安装器", "提权失败：当前账户无法获得管理员权限。\n请右键本程序 -> 以管理员身份运行。", mbIconError)
			return
		}
		selfElevate()
		return
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-gen2":
			gen2Main()
			// v3.0.1: 常驻守护 — 由登录任务带 -guard 启动; 驱动保留并每分钟自查 Gen2
			if hasArg("-guard") && hxcore.DriverStrategy() == hxcore.DriverStrategyResident {
				residentGuard()
			}
			return
		case "-gspensure":
			gspEnsureMain()
			return
		case "-uninstall":
			uninstall()
			return
		case "-status":
			status()
			return
		case "-task":
			// 仅注册 Gen2 登录自启任务(供 -task 模式调用;
			// 由 Go 构造 /TR 引号, 避免 bat 内嵌引号解析出错/闪退)
			regTaskOnly()
			return
		case "-h", "-help", "--help":
			printHelp()
			return
		}
	}
	install()
}

// regTaskOnly: 只注册 Gen2 SYSTEM 任务(不安装驱动/EFI/GSP)。
// -task 模式的最后一步调用本模式 — Go 处理引号。
// v2.6.0: 失败以非零码退出 — bat 的 errorlevel 检查依赖它(此前恒为 0, 检查是死代码)。
func regTaskOnly() {
	if !isAdmin() {
		fmt.Println("[!] 注册计划任务需要管理员权限。")
		msgbox("50HX 安装器", "注册计划任务需要管理员权限。\n请以管理员身份运行。", mbIconError)
		os.Exit(1)
	}
	if err := setupGen2Task(); err != nil {
		fmt.Println("[!]", err)
		msgbox("50HX 安装器", "Gen2 登录自启任务注册失败:\n"+err.Error()+
			"\n\n请确认以管理员身份运行后重试。", mbIconError)
		os.Exit(1)
	}
	// v2.6.0: Run 键 = 登录瞬间先试一次(可能 GPU 未就绪而失败, 静默交权);
	// SYSTEM 任务延迟 30s 再确认。二者由 gen2Main 的单实例互斥体串行化, 不会并发抢驱动。
	setRunKey()
	msgbox("50HX 安装器", "Gen2 登录自启任务已注册。\n登录后会自动执行 Gen2 解锁(静默, 用完即卸)。", mbIconInfo)
}

// selfElevate: 非管理员时 ShellExecute "runas" 重启自身(触发 UAC), 父进程退出
// GUI 子系统下无黑窗; 提权失败以消息框提示
func selfElevate() {
	exe, _ := os.Executable()
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	// 追加 -elevated 标记: 新实例若仍非管理员则禁止再次提权(防无限循环)
	args := append([]string{}, os.Args[1:]...)
	args = append(args, "-elevated")
	params, _ := syscall.UTF16PtrFromString(strings.Join(args, " "))
	r, _, _ := procShellExecuteW.Call(0,
		uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)),
		uintptr(unsafe.Pointer(params)), 0, 1)
	if r <= 32 {
		msgbox("50HX 安装器", fmt.Sprintf("提权失败(错误码 %d)。\n请右键本程序 -> 以管理员身份运行。", r), mbIconError)
	}
	os.Exit(0)
}

var (
	procShellExecuteW = syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW")
)

const (
	mbIconInfo  = 0x40
	mbIconError = 0x10
	mbIconWarn  = 0x30 // MB_ICONWARNING — v2.6.0: EFI 跳过/部分成功等"可继续但要注意"场景
	mbYesNo     = 0x04 // MB_YESNO → 返回 IDYES=6 / IDNO=7
)

var (
	procMsgBoxW     = syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	procCreateMutex = syscall.NewLazyDLL("kernel32.dll").NewProc("CreateMutexW")
)

func msgbox(title, text string, icon uint) {
	// -y / -silent(自动化/自启动) 时不弹框
	if hasArg("-y") || hasArg("-silent") {
		return
	}
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(text)
	procMsgBoxW.Call(0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), uintptr(icon))
}

// msgboxYesNo: 是/否询问。自动模式: -y→true(全自动继续), -silent→false(不打扰)。
func msgboxYesNo(title, text string) bool {
	if hasArg("-y") {
		return true
	}
	if hasArg("-silent") {
		return false
	}
	t, _ := syscall.UTF16PtrFromString(title)
	b, _ := syscall.UTF16PtrFromString(text)
	r, _, _ := procMsgBoxW.Call(0, uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(t)), uintptr(mbYesNo|mbIconInfo))
	return r == 6 // IDYES
}

// setupLog: 输出镜像到日志文件(默认 %TEMP%/<name>, 命令行 -log <file> 优先)
func setupLog(defName string) {
	p := filepath.Join(os.TempDir(), defName)
	if i := argIndex("-log"); i >= 0 && i+1 < len(os.Args) {
		p = os.Args[i+1]
	}
	if f, err := os.Create(p); err == nil {
		os.Stdout = f
		os.Stderr = f
		fmt.Fprintf(f, "==== 50HX tool %s ====\n", time.Now().Format("2006-01-02 15:04:05"))
	}
}

// AttachLogSink: v2.6.0 GUI 用 — 用 os.Pipe 把后续 fmt.* 输出分流到 日志文件+UI。
// fmt.* 每次调用读 os.Stdout 变量; 但 os.Stdout 本身是 *os.File 具体类型,
// 不能赋 io.Writer, 故替换为管道写端, 由读协程同时写原文件与 GUI 日志面板。
func AttachLogSink(w io.Writer) {
	r, pw, err := os.Pipe()
	if err != nil {
		return
	}
	orig := os.Stdout // setupLog 建立的日志文件(或 GUI 下的无效控制台句柄)
	os.Stdout = pw
	os.Stderr = pw
	go func() {
		defer r.Close()
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				orig.Write(buf[:n]) // 落日志文件(GUI 模式下失败可忽略)
				w.Write(buf[:n])    // 喂 GUI 日志面板
			}
			if rerr != nil {
				return
			}
		}
	}()
}

// lockOnce: 单实例互斥; 返回 nil 表示已有实例在跑
func lockOnce(name string) func() {
	n, _ := syscall.UTF16PtrFromString(name)
	h, _, e := procCreateMutex.Call(0, 0, uintptr(unsafe.Pointer(n)))
	if h == 0 {
		return nil
	}
	if e == syscall.ERROR_ALREADY_EXISTS {
		syscall.CloseHandle(syscall.Handle(h))
		return nil
	}
	return func() { syscall.CloseHandle(syscall.Handle(h)) }
}

func hasArg(name string) bool {
	for _, a := range os.Args {
		if a == name {
			return true
		}
	}
	return false
}

func argIndex(name string) int {
	for i, a := range os.Args {
		if a == name {
			return i
		}
	}
	return -1
}

func printHelp() {
	fmt.Println("CMP 50HX Windows 解锁一键安装工具")
	fmt.Println("  用法: 50HXInstaller.exe            # 安装(需管理员)")
	fmt.Println("       50HXInstaller.exe -gen2      # 立即执行 Gen2 解锁")
	fmt.Println("       50HXInstaller.exe -uninstall # 卸载")
	fmt.Println("       50HXInstaller.exe -status    # 状态")
}

// ===================== 底层 =====================

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
		// TokenElevation 可能因受限环境(沙箱/服务)误报 0, 再试 SCM 全权
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err == nil {
		windows.CloseServiceHandle(scm)
		return true
	}
	return false
}

// enableGsp: 设 EnableGpuFirmware=1 (需管理员)
func enableGsp() error {
	key := hxcore.FindGpuClassKey()
	if key == "" {
		return errors.New("找不到 50HX 的设备注册表键 (Class 子键)")
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(gpuEnableFw, 1)
}

// disableGsp: 删 EnableGpuFirmware (卸载用, 恢复默认关)
func disableGsp() {
	key := hxcore.FindGpuClassKey()
	if key == "" {
		return
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	k.DeleteValue(gpuEnableFw)
}

// ensureGspSilent: 确保 GSP 启用 (EnableGpuFirmware=1)。
// 供 -gen2(登录自启动)调用: 若 GSP 被改回(≠1)则重新启用。
// 写 HKLM 需管理员: 当前是管理员直接写; 否则注册一次性 SYSTEM 计划任务
// (SYSTEM 权限写 HKLM 无需 UAC, 无窗口)。
// 返回 true = GSP 已启用或已安排重设。
func ensureGspSilent() bool {
	if hxcore.GspEnabled() {
		return true // 已启用
	}
	fmt.Println("[GSP] EnableGpuFirmware 被改回, 重新启用...")
	if isAdmin() {
		if err := enableGsp(); err != nil {
			fmt.Println("[GSP] 重设失败:", err)
			return false
		}
		fmt.Println("[GSP] 已重设 EnableGpuFirmware=1 (重启后 GSP-RM 生效)")
		return true
	}
	// 非管理员: 用 SYSTEM 计划任务一次性重设 (无 UAC 弹窗)
	exe, _ := os.Executable()
	abs, _ := filepath.Abs(exe)
	tn := "50HXGspEnsure"
	if out, err := hxcore.RunOut("schtasks.exe", "/create", "/tn", tn,
		"/tr", fmt.Sprintf("\"%s\" -gspensure -silent", abs),
		"/sc", "once", "/st", "00:00", "/ru", "SYSTEM", "/f"); err != nil {
		fmt.Printf("[GSP] 计划任务创建失败: %s\n", strings.TrimSpace(out))
		return false
	}
	hxcore.RunOut("schtasks.exe", "/run", "/tn", tn)
	hxcore.RunOut("schtasks.exe", "/delete", "/tn", tn, "/f")
	fmt.Println("[GSP] 已通过 SYSTEM 任务重设 EnableGpuFirmware=1")
	return true
}

// gspEnsureMain: -gspensure 模式 (SYSTEM 计划任务调用, 只重设 GSP 后退出)
func gspEnsureMain() {
	if isAdmin() {
		if err := enableGsp(); err != nil {
			fmt.Println("[GSP] gspensure 重设失败:", err)
			return
		}
		fmt.Println("[GSP] gspensure: EnableGpuFirmware=1 已设置")
	}
}

func copyEmbedTo(target string, src string) error {
	data, err := embedded.ReadFile("embed/" + src)
	if err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o644)
}

// deployEspEfi: 双路部署 50HXUNLK.EFI 到已挂载的 ESP <esp>。
//
//	A. \EFI\50HX\50HXUNLK.EFI   — BCD 启动项引用路径
//	B. \EFI\Boot\bootx64.efi    — UEFI 标准回退路径 (固件无条件尝试的最后手段;
//	   解决社区大量"装完重启直接进 Windows 没跑解锁"——主板忽略非标准目录)
//
// 备份规则: 若目标 bootx64.efi 存在且不是本工具部署过的副本, 先备份为
//
//	bootx64.efi.50hx.bak (卸载时恢复)。已部署过(.bak 已存在)则直接覆盖。
//
// 返回 fallback 是否新备份了原文件。
func deployEspEfi(esp string) (backedUp bool, err error) {
	// 读取 embed 一次, 两个路径共用
	data, rerr := embedded.ReadFile("embed/50HXUNLK.EFI")
	if rerr != nil {
		return false, rerr
	}
	// 写盘前校验 embed 数据本身完整 (PE 头 + 长度合理, 防 embed 损坏)
	if len(data) < 0x2000 { // < 8KB 的 EFI 文件必为损坏
		return false, fmt.Errorf("内嵌 50HXUNLK.EFI 数据异常 (%d bytes)", len(data))
	}
	if !bytes.HasPrefix(data, []byte("MZ")) {
		return false, errors.New("内嵌 50HXUNLK.EFI 不是有效 PE 镜像(缺 MZ 头)")
	}

	// A. 主路径
	dirA := esp + ":" + efiDir // Y:\EFI\40HX
	if merr := os.MkdirAll(dirA, 0o644); merr != nil {
		return false, merr
	}
	pA := filepath.Join(dirA, efiFile)
	if werr := writeVerified(pA, data); werr != nil {
		// 写失败或校验不一致 → 删掉可能半截的文件, 避免被 BCD 引用成坏引导
		os.Remove(pA)
		return false, werr
	}
	fmt.Printf("    [A] %s  (%d bytes, 校验 OK)\n", "\\EFI\\50HX\\"+efiFile, len(data))

	// B. 标准回退路径
	dirB := esp + ":" + efiStdDir // Y:\EFI\Boot
	if merr := os.MkdirAll(dirB, 0o644); merr != nil {
		return false, merr
	}
	pB := filepath.Join(dirB, efiStdF) // bootx64.efi
	pBak := pB + efiBakExt             // bootx64.efi.50hx.bak
	if _, berr := os.Stat(pBak); berr != nil {
		// 无备份记录 → 若目标存在且不是我们已部署的副本, 先备份
		if old, oerr := os.ReadFile(pB); oerr == nil && !bytes.Equal(old, data) {
			if cerr := os.Rename(pB, pBak); cerr != nil {
				return false, fmt.Errorf("备份原 %s 失败: %v", pB, cerr)
			}
			fmt.Printf("    [B] 原 %s 已备份为 %s\n", efiStdF, efiStdF+efiBakExt)
			backedUp = true
		} else if oerr != nil {
			// 目标不存在: 无备份(本来就是空位)
		}
	}
	if werr := writeVerified(pB, data); werr != nil {
		os.Remove(pB)
		return backedUp, werr
	}
	fmt.Printf("    [B] %s  (%d bytes, 校验 OK)\n", "\\EFI\\Boot\\"+efiStdF, len(data))
	return backedUp, nil
}

// writeVerified: 写文件后立即读回比对 — 防止写入中断/半截导致引导损坏。
// 不一致则删除并返回错误(调用方据此中止, 不让坏文件留在引导路径)。
func writeVerified(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	rb, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("写后校验读取失败 %s: %v", path, err)
	}
	if !bytes.Equal(rb, data) {
		return fmt.Errorf("写后校验不一致 %s (%d ≠ %d bytes)", path, len(rb), len(data))
	}
	return nil
}

// alreadyInstalled: 检测是否已安装过(避免无意义/重复的覆盖安装)。
// 判据: ① 固件启动项 "50HX Unlock" 存在; ② ESP 上已有 \EFI\50HX\50HXUNLK.EFI。
// 任一命中即认为装过 — 用于重入提示(不会因此阻止用户, 仅弹确认)。
func alreadyInstalled() bool {
	// ① bcdedit 固件枚举(不挂 ESP, 快速)
	if out, _ := hxcore.RunOut("bcdedit.exe", "/enum", "firmware"); strings.Contains(out, bootDesc) {
		return true
	}
	// ② ESP 文件
	esp := hxcore.MountESP()
	if esp == "" {
		return false // 挂不上 ESP 时保守视为未装(后面 [5/8] 会报错引导)
	}
	defer hxcore.UnmountESP(esp)
	if _, err := os.Stat(esp + ":" + efiDir + "\\" + efiFile); err == nil {
		return true
	}
	return false
}

// verifyBootEntry: 读回 {fwbootmgr} displayorder, 确认 50HX Unlock 是否在首位。
// 返回 (exists, isFirst, displayOrder描述)。
// 用 bcdedit /enum firmware 读固件 NVRAM — 若固件忽略 bcdedit 的写入,
// 这里会如实反映(不在列表/不在首位), 从而让安装器给出 BIOS 手动指引。
// 注意: bcdedit 输出为 GBK, 中文系统"标识符/说明"是乱码; 但字段值
// (guid / displayorder / 50HX Unlock / path) 均为 ASCII, 按块解析可靠。
func verifyBootEntry() (bool, bool, string) {
	out, err := hxcore.RunOut("bcdedit.exe", "/enum", "firmware")
	if err != nil {
		return false, false, "(bcdedit 读取失败: " + err.Error() + ")"
	}
	lines := strings.Split(out, "\r\n")
	if len(lines) < 2 {
		lines = strings.Split(out, "\n")
	}

	// 1. 收集 displayorder 下的 GUID 序列(固件实际启动顺序)
	var order []string
	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if strings.HasPrefix(t, "displayorder") {
			// 首个 GUID 可能同行: "displayorder {guid}"
			if m := guidRe().FindString(t); m != "" {
				order = append(order, strings.Trim(m, "{}"))
			}
			// 后续缩进行 {guid}
			for j := i + 1; j < len(lines); j++ {
				s := strings.TrimSpace(lines[j])
				if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
					order = append(order, strings.Trim(s, "{}"))
				} else if s != "" {
					break
				}
			}
			break // displayorder 只在 {fwbootmgr} 段, 取首个即可
		}
	}

	// 2. 找 description 为 "50HX Unlock" 的块的 GUID
	target := ""
	for i := 0; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "description") &&
			strings.Contains(lines[i], bootDesc) {
			// 往上找最近的 {guid} 行 = 该块 identifier
			for j := i - 1; j >= 0 && j > i-6; j-- {
				if m := guidRe().FindString(lines[j]); m != "" {
					target = strings.Trim(m, "{}")
					break
				}
			}
			break
		}
	}
	if target == "" {
		joined := strings.Join(order, " > ")
		if joined == "" {
			joined = "(固件无 displayorder 条目)"
		}
		return false, false, joined
	}
	if len(order) == 0 {
		return true, false, "(displayorder 为空)"
	}
	isFirst := order[0] == target
	return true, isFirst, strings.Join(order, " > ")
}

var _guidRe = regexp.MustCompile(`\{([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}`)

func guidRe() *regexp.Regexp { return _guidRe }

// ===================== 安装 =====================

// applyPowerSettings: 快速启动 + PCIe ASPM 两项电源优化(v2.6.0 [3.6/8] 段抽取,
// v2.6.0 GUI 策略页复用)。幂等: 原本已关则不动; 返回逐项说明行。
func applyPowerSettings() []string {
	notes := []string{}
	if hxcore.FastStartupOn() {
		if err := hxcore.SetFastStartupOff(); err != nil {
			notes = append(notes, fmt.Sprintf("快速启动关闭失败: %v (不影响安装, 建议电源选项手动关)", err))
		} else {
			notes = append(notes, "快速启动已关闭(原为开): 关机将走完整 UEFI 引导; 电源选项可恢复")
		}
	} else {
		notes = append(notes, "快速启动: 原本已关(OK)")
	}
	if ac, dc, ok := hxcore.ASPMSavings(); !ok {
		notes = append(notes, "PCIe ASPM: 本机未公开该设置, 跳过")
	} else if ac == 0 && dc == 0 {
		notes = append(notes, "PCIe ASPM: 原本已关(OK)")
	} else {
		if err := hxcore.SetASPMOff(); err != nil {
			notes = append(notes, fmt.Sprintf("ASPM 关闭失败: %v", err))
		} else {
			notes = append(notes, fmt.Sprintf("PCIe ASPM 已关闭(原 AC=%d/DC=%d): 减少空闲降到 Gen1; 恢复: powercfg 命令见 README", ac, dc))
		}
	}
	return notes
}

// installEFI: ESP 双路部署 50HXUNLK.EFI + 固件启动项(v2.6.0 [5/8]+[6/8] 段抽取,
// v2.6.0 GUI 组件安装页复用)。返回 EFI 是否部署成功;
// [7/8] Gen2 任务注册不依赖此结果(EFI 失败只跳过 EFI 两步 — 社区 #2/#5/#6/#7 统一根因修复)。
func installEFI() bool {
	//    主路径  \EFI\50HX\50HXUNLK.EFI  — BCD 启动项引用
	//    fallback \EFI\Boot\bootx64.efi   — UEFI 标准回退路径, 解决部分主板
	//    忽略 BCD displayorder / 不认非标准目录(社区"装完重启没反应"主因)。
	//    原 bootx64.efi 备份为 bootx64.efi.50hx.bak, 卸载时恢复。
	efiOK := false
	fmt.Println("    · 部署解锁 EFI 到系统 EFI 分区(双路)...")
	esp := hxcore.MountESP()
	if esp == "" {
		if hxcore.FirmwareIsLegacy() {
			fmt.Println("[!] 本系统为传统 BIOS(Legacy)+MBR 引导 — 没有 EFI 分区, 解锁 EFI 无法部署。")
			fmt.Println("    算力解锁需要 UEFI+GPT: 请先用微软 mbr2gpt 无损转换(完整步骤见弹窗),")
			fmt.Println("    转换完成并改 UEFI 引导后重跑本安装器。")
			fmt.Println("    [i] Gen2 登录自启不受影响, 继续注册(见 [7/8])。")
			msgbox("50HX 安装器 (需要先转换硬盘为 GPT)",
				"本系统是传统 BIOS(Legacy)+MBR 引导, 没有 EFI 分区,\n"+
					"算力解锁 EFI 无法部署 — 这就是\"EFI 装不上\"的原因。\n\n"+
					"请先转成 UEFI+GPT(微软官方无损转换, 不动数据):\n"+
					"  1. 备份重要数据; 确认未启用 BitLocker(有则先暂停)\n"+
					"  2. 管理员命令提示符运行:  mbr2gpt /validate /allowfullos\n"+
					"  3. 显示 Validation completed successfully 后运行:\n"+
					"        mbr2gpt /convert /allowfullos\n"+
					"  4. 重启进 BIOS, 把启动模式从 Legacy 改为 UEFI(关 CSM)\n"+
					"  5. 进 Windows 后重新运行本安装器\n\n"+
					"注意: 转换不可逆; 需 Win10 1703+ / Win11 且主板支持 UEFI。\n"+
					"本次安装将继续完成 Gen2 部分(算力解锁等转换后重跑安装器)。",
				mbIconWarn)
		} else {
			fmt.Println("[!] 无法挂载 EFI 分区(mountvol /S 失败)")
			fmt.Println("    系统是 UEFI, 常见原因: BitLocker/第三方加密未暂停、ESP 分区异常。")
			fmt.Println("    可手动: mountvol S: /S, 复制 50HXUNLK.EFI 到 S:\\EFI\\50HX\\, mountvol S: /D")
			msgbox("50HX 安装器 (EFI 分区挂载失败)",
				"无法挂载 EFI 分区 (mountvol /S 失败), 解锁 EFI 本次未部署。\n"+
					"系统引导不受影响。\n\n"+
					"常见原因: BitLocker/第三方加密未暂停、ESP 分区异常。\n"+
					"可手动部署(见日志与《EFI应急修复指南.md》)。\n\n"+
					"本次安装将继续完成 Gen2 部分, 算力解锁待 EFI 部署成功后生效。",
				mbIconWarn)
		}
		return false
	}
	fmt.Printf("    ESP 挂载于 %s: \\\n", esp)
	fb, err := deployEspEfi(esp)
	hxcore.UnmountESP(esp)
	if err != nil {
		fmt.Println("[!] 复制 EFI 失败:", err)
		msgbox("50HX 安装器 (EFI 写入失败)",
			"复制解锁 EFI 到 ESP 失败(已做写后校验, 坏文件不会残留):\n"+err.Error()+
				"\n\n系统引导未受影响, 重启应能正常进 Windows。\n\n"+
				"如需手动部署, 见同目录《EFI应急修复指南.md》中\n"+
				"“手动部署”一节。\n\n"+
				"本次安装将继续完成 Gen2 部分。", mbIconWarn)
		return false
	}
	if fb {
		fmt.Println("    [!] 检测到原 bootx64.efi, 已备份为 bootx64.efi.50hx.bak")
	}
	efiOK = true

	// BootOrder (v2.4: 写回验证 + BIOS 指引弹框); 仅 EFI 部署成功才执行
	fmt.Println("    · 设置固件启动项(50HX Unlock 置顶)...")
	bootOK := false
	if err := setupBootEntry(); err != nil {
		fmt.Println("[!] 自动设置启动项失败:", err)
	} else {
		if ex, first, ord := verifyBootEntry(); ex {
			bootOK = first
			if first {
				fmt.Println("    启动项已置顶并验证通过 (固件 displayorder 首位)")
			} else {
				fmt.Println("    [!] 启动项已创建, 但不在 displayorder 首位:")
				fmt.Println("        当前固件顺序: " + ord)
				fmt.Println("        请进 BIOS 手动将 '50HX Unlock' 设为第一启动项(见弹窗)")
			}
		} else {
			fmt.Println("    [!] 未能在固件启动列表中找到 '50HX Unlock' 项")
			fmt.Println("        (部分主板忽略 BCD 写入, 请进 BIOS 手动添加/置顶)")
		}
	}
	if !bootOK {
		// BIOS 指引弹窗 (社区用户不看日志/README 的关键一步)
		msgbox("50HX 安装器 (重要: 请按提示操作)",
			"自动启动项未被固件接受。\n"+
				"请重启并按 Del/F2 进 BIOS, 完成以下设置(否则不解锁):\n\n"+
				"1. 关闭 Secure Boot(已开则未签名 EFI 会被拒)\n"+
				"2. 关闭 Fast Boot / 快速启动(若有)\n"+
				"3. 在 [启动顺序/Boot Priority] 中把 '50HX Unlock' 设为第一项\n"+
				"   或手动从启动设备选择 \\EFI\\50HX\\50HXUNLK.EFI\n"+
				"4. 若列表只有 Windows Boot Manager:\n"+
				"   - 部分主板需关闭 CSM(纯 UEFI)后才会出现该启动项\n"+
				"   - 或直接选 UEFI 盘符启动(走 bootx64 回退)\n\n"+
				"安装器已把解锁 EFI 同时部署到:\n"+
				"  \\EFI\\50HX\\50HXUNLK.EFI  (BCD 路径)\n"+
				"  \\EFI\\Boot\\bootx64.efi    (标准回退路径)\n\n"+
				"详细日志: "+filepath.Join(os.TempDir(), "50HX_installer.log"),
			mbIconError)
	}
	return efiOK
}

func install() {
	fmt.Println("==============================================")
	fmt.Println("  CMP 50HX Windows Unlock Installer v3.0.0")
	fmt.Println("  Tensor 解锁(EFI V70 + GSP 启用) + PCIe Gen2 + 自启动")
	fmt.Println("==============================================")

	if !isAdmin() {
		fmt.Println("[!] 需要管理员权限。")
		msgbox("50HX 安装器", "需要管理员权限。\n请右键本程序 -> 以管理员身份运行。", mbIconError)
		return
	}
	if lockOnce(`Local\40HXInstaller_v1`) == nil {
		msgbox("50HX 安装器", "安装器已在运行, 请勿重复点击。", mbIconInfo)
		return
	}

	// 0. 重入检测: 已装过(固件启动项/GSP 键已存在) → 确认后再覆盖,
	//    避免用户误以为需要反复安装、或在不知情下覆盖现有部署。
	if alreadyInstalled() {
		fmt.Println("[!] 检测到 50HX 解锁已安装过(启动项/GSP 键存在)。")
		if !msgboxYesNo("50HX 安装器",
			"检测到 50HX 解锁已安装过。\n\n"+
				"再次安装会覆盖现有部署(驱动与启动项会更新, 不会损坏系统引导)。\n"+
				"如果是想修复异常/升级, 选\"是\"继续;\n"+
				"如果只是误打开, 选\"否\"保持现状即可。\n\n"+
				"继续重新安装?") {
			fmt.Println("已取消 — 保持现有安装不变。")
			return
		}
		fmt.Println("    用户确认, 继续覆盖安装。")
	}

	// 1. GPU 检测
	fmt.Print("[1/8] 检测 GPU ... ")
	if !hxcore.FindGPU() {
		fmt.Println("未找到 " + gpuVenDev)
		fmt.Println("[!] 未检测到 CMP 50HX。中止。")
		msgbox("50HX 安装器", "未检测到 CMP 50HX 显卡 (VEN_10DE&DEV_1E09)。\n安装中止。", mbIconError)
		return
	}
	fmt.Println("CMP 50HX 已找到")

	// 2. Secure Boot
	fmt.Print("[2/8] Secure Boot 检查 ... ")
	if hxcore.SecureBootOn() {
		fmt.Println("开启!")
		fmt.Println("[!] Secure Boot 开启时, 未签名 EFI(40HXUNLK) 会被固件拒绝。")
		msgbox("50HX 安装器 (需要关闭 Secure Boot)",
			"检测到 Secure Boot 开启, 未签名的解锁 EFI 会被固件拒绝。\n\n"+
				"请重启进 BIOS 关闭后再运行本安装器:\n"+
				"  1. 重启, 开机按 Del / F2(部分主板 F1/F10/F12)进 BIOS\n"+
				"  2. 找 Security / Boot / 启动 选项卡\n"+
				"  3. 将 Secure Boot 设为 Disabled\n"+
				"     (若灰显, 先设 CSM/兼容模式 或恢复默认安全设置)\n"+
				"  4. 保存退出(F10)后重新运行本程序\n\n"+
				"这是解锁必需的: 50HX 解锁 EFI 无微软签名。",
			mbIconError)
		return
	}
	fmt.Println("关闭/不可用(OK)")

	// 3. 测试签名 (v2.5 不需要 — BYOVD 预签名驱动普通模式即可加载)
	fmt.Print("[3/8] 测试签名 ... ")
	if hxcore.TestSigningOn() {
		fmt.Println("已开启 — v2.5 不需要, 装完可 bcdedit /set testsigning off 关闭")
	} else {
		fmt.Println("关闭(OK) — v2.5 全程免测试签名")
	}

	// 3.5 GSP 启用 (v2.3: 解锁不黑屏的关键!)
	// 50HX 默认 GSP 关(CPU-RM 模式) -> EFI 解锁后 nvlddmkm 拒绝 -> Code43 黑屏
	// EnableGpuFirmware=1 -> GSP-RM 管理 SEC2/booter -> 接受解锁状态
	fmt.Print("[3.5/8] 启用 GSP (EnableGpuFirmware) ... ")
	if hxcore.GspEnabled() {
		if sub, _, fw := hxcore.GspDiag(); sub != "" {
			fmt.Printf("已启用(OK) — Class\\%s EnableGpuFirmware=%d\n", sub, fw)
		} else {
			fmt.Println("已启用(OK)")
		}
	} else {
		if err := enableGsp(); err != nil {
			// v2.4.1: 附带 AdapterString 诊断 — 伪装驱动(雨糖识别成2070等)会命中此分支
			_, adapterDiag, _ := hxcore.GspDiag()
			fmt.Println("设置失败:", err)
			if adapterDiag != "" && !strings.Contains(adapterDiag, "无 CMP 50HX") {
				fmt.Println("    [!] 实际 AdapterString:", adapterDiag)
			} else if adapterDiag != "" {
				fmt.Println("    [!]", adapterDiag)
			}
			fmt.Println("    [!] 若驱动是伪装版(识别成 2070 等): 换未伪装版驱动或手动设 GSP")
			msgbox("50HX 安装器", "设置 EnableGpuFirmware=1 失败(需管理员)。\n解锁后可能黑屏/掉驱动。\n错误: "+err.Error()+"\n若驱动是伪装版(识别成2070等),请换未伪装驱动或用 -status 查 AdapterString。", mbIconError)
			return
		}
		fmt.Println("已设 EnableGpuFirmware=1 (重启生效)")
		fmt.Println("    [!] GSP 必需: 否则 EFI 解锁后驱动不认 -> Code43 黑屏")
	}

	// 3.6 系统电源设置 (v2.6.0: 社区 v2.4.5 排障结论)
	//     快速启动: "关机→再开"走休眠恢复, 不做完整 UEFI 引导, EFI 可能不跑
	//     PCIe ASPM: 开启时空闲会降到 Gen1, 登录后实测容易被误读成"Gen2 失败"
	//     两项幂等设置, 只在当前为开时改; 均可在电源选项恢复, 不碰其他电源策略
	fmt.Print("[3.6/8] 电源设置(快速启动 + PCIe 链路省电) ... ")
	pwrNotes := applyPowerSettings()
	fmt.Println("完成")
	for _, n := range pwrNotes {
		fmt.Println("    - " + n)
	}

	// 4. 驱动安装
	fmt.Println("[4/8] 准备 Gen2 BYOVD 驱动(ThrottleStop + WinRing0)...")
	installDrivers()

	// 4.5 Defender 精确排除(防杀软误删驱动文件导致 Gen2 自启失败)
	//     只加我们自己的驱动/备份/发布目录, 不关任何系统防护。
	fmt.Print("[4.5/8] Defender 排除(防误删) ... ")
	if err := hxcore.AddDefenderExclusions(); err != nil {
		fmt.Println("未执行(可忽略):", err)
	} else {
		fmt.Println("已加白 ThrottleStop/WinRing0 驱动文件与备份目录")
	}

	// 5+6. EFI 部署与启动项 (v2.6.0: 抽取为 installEFI, GUI 按组件复用)
	fmt.Println("[5/8]+[6/8] 部署解锁 EFI 与固件启动项(双路写入 + displayorder 置顶)...")
	efiOK := installEFI()

	// 7. Gen2 自启动(安装时不 retrain!)
	// 重要: 安装过程中绝不执行 Gen2 PCIe 重训。此时 nvlddmkm 正占用 GPU,
	// 强行 retrain 会让 GPU/链路进入异常状态, 导致下次开机 EFI 接力或
	// nvlddmkm 初始化失败(实测: 设备报 code19 / Windows 启动异常进安全模式)。
	// 正确时机 = 重启后登录时执行(与手动方案一致, 已验证稳定)。
	// v2.6.0: 两路互斥串行设计 — Run 键登录瞬间先试 + SYSTEM 任务延迟30s确认;
	// 单实例互斥体(gen2AcquireSingleInstance)保证二者不会同时进入驱动加载临界区。
	// Run 键在普通权限下无法 sc start 驱动 → 自动交权给 SYSTEM 任务(静默)。
	fmt.Println("[7/8] 注册 Gen2 登录自启动(SYSTEM 任务 + Run 键, 互斥串行)...")
	setRunKey()
	if err := setupGen2Task(); err != nil {
		// v2.6.0: 任务是 Gen2 链的命脉, 注册失败必须让用户看见并可一键修复
		fmt.Println("[!]", err)
		msgbox("50HX 安装器 (Gen2 自启注册失败)",
			"Gen2 登录自启任务注册失败 — 登录后不会自动解锁 Gen2。\n\n"+
				"请稍后右键以管理员身份运行一次:\n"+
				"  50HXInstaller.exe -task\n\n"+
				"其余安装步骤已完成。", mbIconWarn)
	}

	fmt.Println()
	fmt.Println("安装完成!")
	if efiOK {
		fmt.Println("  下次重启: 固件将自动运行 50HX Unlock (Tensor 解锁) -> 自动进 Windows")
	} else {
		fmt.Println("  [!] EFI 算力解锁本次未部署(见 [5/8] 说明) — 算力暂不会解锁,")
		fmt.Println("      按 [5/8] 弹窗指引(mbr2gpt/手动部署)处理后重跑本安装器即可。")
	}
	fmt.Println("  GSP 已启用: 驱动以 GSP-RM 模式接管 GPU, 解锁后不再黑屏/掉驱动")
	fmt.Println("  登录后: Gen2 自动解锁 (已注册自启动, 无窗口静默)")
	fmt.Println("  [!] 安装时不重训 PCIe, 重启后登录时才执行(避免与显卡驱动冲突)")
	fmt.Println("  重启后验证: 双击 50HXCheck.exe 查看解锁状态(SS0=0x88888888 即成功)")
	fmt.Println("  若 testsigning 刚开启: 请先重启一次使驱动可加载")
	// v2.4: 完成弹框含关键 BIOS/重启指引(社区用户不依赖 README 也能操作)
	// v2.6.0: EFI 成败给出不同指引; 告知电源设置已自动调整及恢复方式
	efiNote := ""
	if efiOK {
		efiNote = "重启时请注意:\n" +
			"  · 若黑屏/显示 50HX 文字日志约 10~30 秒, 属正常(正在解锁)\n" +
			"  · 解锁完成后会自动进入 Windows\n\n" +
			"若重启后直接进了 Windows(没跑解锁), 请进 BIOS(Del/F2):\n" +
			"  1. 关闭 Secure Boot(未签名 EFI 需要)\n" +
			"  2. 关闭 Fast Boot\n" +
			"  3. 把 '50HX Unlock' 设为第一启动项\n" +
			"     (若列表只有 Windows Boot Manager, 关 CSM 后再看)\n"
	} else {
		efiNote = "[!] 本次 EFI 算力解锁未部署(原因见上方弹窗/日志):\n" +
			"  · 算力暂不会解锁, 按指引处理后重跑安装器即可\n" +
			"  · Gen2 自启已注册, 不受影响\n"
	}
	msgbox("50HX 安装器 (安装完成)",
		"✅ 安装完成! "+map[bool]string{true: "重启后将自动执行解锁。", false: "Gen2 部分已就绪。"}[efiOK]+"\n\n"+
			efiNote +
			"\n重启进系统后:\n"+
			"  · 双击同目录的 50HXCheck.exe 验证 — 显示\n"+
			"    '解锁成功: Tensor 满血(SS0=0x88888888)' 即完成\n"+
			"  · 若提示未解锁, 它会给下一步(如开 Above 4G)\n\n"+
			"· 测试签名若刚开启: 先重启一次驱动才可加载\n"+
			"· GSP 已启用(EnableGpuFirmware=1): 解锁不黑屏的关键\n"+
			"· 已自动关闭快速启动与 PCIe 链路省电(ASPM):\n"+
			"  前者保证关机再开也走完整 UEFI 引导, 后者减少空闲降到 Gen1;\n"+
			"  恢复方式见 README §2.4\n"+
			"· 登录后 Gen2 自动解锁(静默)\n\n"+
			"详细日志: "+filepath.Join(os.TempDir(), "50HX_installer.log"),
		mbIconInfo)
}

func installDrivers() {
	sysDir := os.Getenv("SystemRoot") + "\\System32\\drivers"
	svcRunning := func(name string) bool {
		out, _ := hxcore.RunOut("sc.exe", "query", name)
		return strings.Contains(out, "RUNNING")
	}
	// v2.5: 不再常驻 50hx_bridge(需测试签名)。Gen2 改 BYOVD:
	//   ThrottleStop(任意物理内存写, EV 预签名) + WinRing0(PCI config) —
	//   两者普通模式(testsigning off)即可加载。安装阶段仅放好驱动文件 +
	//   注册 demand 服务; 真正的加载与自清理由登录后的 -gen2(SYSTEM 任务)
	//   完成 → 用完即卸, 游戏时系统无第三方驱动。
	tsApp := throttleStopAppRunning()
	for _, d := range []struct{ name, file string }{
		{"ThrottleStop", "ThrottleStop.sys"},
		{"WinRing0_1_2_0", "WinRing0x64.sys"},
	} {
		dst := filepath.Join(sysDir, d.file)
		// 本机装了 ThrottleStop 软件 → 复用其同名驱动, 绝不覆盖/删除(避免冲突+写保护)
		if tsApp {
			fmt.Printf("  检测到 ThrottleStop 软件, 复用其 %s 驱动(不覆盖/不删)\n", d.name)
			continue
		}
		if svcRunning(d.name) {
			fmt.Printf("  %s 已在运行, 跳过覆盖(保持当前状态)\n", d.name)
			continue
		}
		hxcore.RunOut("sc.exe", "stop", d.name)
		// 留一份到 %ProgramData%\50HXUnlock\drivers 作为持久备份源
		// (40HXCheck 实测/Gen2 临时部署都从这里取; System32 的会被用完即卸删除)
		pdDir := filepath.Join(os.Getenv("ProgramData"), "50HXUnlock", "drivers")
		os.MkdirAll(pdDir, 0o755)
		copyEmbedTo(filepath.Join(pdDir, d.file), d.file)
		if err := copyEmbedTo(dst, d.file); err != nil {
			if _, statErr := os.Stat(dst); statErr != nil {
				fmt.Printf("  [!] 复制 %s 失败: %v\n", d.file, err)
				continue
			}
		} else {
			fmt.Printf("  已复制 %s\n", d.file)
		}
		ensureService(d.name, d.file)
	}
	fmt.Println("  Gen2 驱动文件已就绪(demand), 登录后由 SYSTEM 任务临时加载并自清理")
}

// ensureService: 仅注册(或更新)驱动服务, 不在此处加载。
// 安装阶段加载 50hx_bridge(映射 GPU BAR0)会与正在运行的 nvlddmkm 争用硬件,
// 实测导致 50HX 设备报 code19 / 后续启动异常。加载推迟到重启后登录时的 -gen2。
// v2.4.6 关键修复(社区 #1/#2 根因):
//
//	驱动服务注册为 start=demand(手动), 需在登录后由 -gen2 拉起。
//	而 -gen2 走 Run 键以普通用户权限运行 → sc start 需要管理员 →
//	"[SC] StartService: OpenService 失败 5: 拒绝访问" → 驱动永远起不来
//	→ Gen2 永远失败(用户现象: 算力解锁 OK 但 Gen2 ✗)。
//	正解 = 保持 demand(不改成 auto! 详见下), 并把 -gen2 的执行权限升到
//	SYSTEM: 注册 SYSTEM 计划任务(登录时触发 + 延迟 30s)跑 -gen2 -silent,
//	既不需要 UAC 弹窗, 又保留"登录后才加载驱动"的安全时序。
//
// 为什么不改成 start=auto: type=kernel auto 驱动在开机早期由 SCM 加载,
// 会与随后初始化的 nvlddmkm 争用 GPU BAR0 — 历史上实测导致 50HX 报
// code19 / Windows 启动异常进安全模式。demand + 登录后加载是经过验证的时序。
func ensureService(name string, sysFile string) {
	bin := fmt.Sprintf("\\SystemRoot\\System32\\drivers\\%s", sysFile)
	// 创建(已存在会失败, 忽略); 启动类型 demand — 由 SYSTEM 任务登录后拉起
	hxcore.RunOut("sc.exe", "create", name, "type=", "kernel", "start=", "demand", "binPath=", bin)
	out, err := hxcore.RunOut("sc.exe", "query", name)
	if err != nil || !strings.Contains(out, "STATE") {
		fmt.Printf("  [!] 注册服务 %s 失败: %s\n", name, strings.TrimSpace(out))
		return
	}
	// 纠正被安全软件/策略改错的启动类型(Disabled 会导致 Gen2 永远拉不起)。
	// 启动类型在 sc qc, 不在 query; 状态(STOPPED/RUNNING)在 query。
	start := "demand"
	if qc, qerr := hxcore.RunOut("sc.exe", "qc", name); qerr == nil {
		qcu := strings.ToUpper(qc)
		switch {
		case strings.Contains(qcu, "DISABLED"):
			hxcore.RunOut("sc.exe", "config", name, "start=", "demand")
			start = "demand(原被改 DISABLED, 已修正)"
		case strings.Contains(qcu, "AUTO_START"):
			start = "auto(注意: 应为 demand)"
		}
	}
	stateS := "?"
	switch {
	case strings.Contains(out, "RUNNING"):
		stateS = "RUNNING"
	case strings.Contains(out, "STOPPED"):
		stateS = "STOPPED"
	}
	fmt.Printf("  服务 %s 已注册 (%s, %s), 登录后由 SYSTEM 任务加载\n", name, start, stateS)
}

// ensureSvcLoaded: 确保驱动服务已注册并加载。
// v2.4.6: 由 SYSTEM 任务(或管理员手动)调用时 sc start 才有权限;
// 普通权限(Run 键兜底)下失败属预期 — 静默交给 SYSTEM 任务处理。

// throttleStopAppRunning: 本机 ThrottleStop 软件进程检测(第三方占用驱动时跳过自清理)。

func throttleStopAppRunning() bool {
	out, _ := hxcore.RunOut("tasklist.exe", "/FI", "IMAGENAME eq ThrottleStop.exe")
	return strings.Contains(out, "ThrottleStop.exe")
}

// redeployDriverFile: v2.6.0 - 杀软可能删驱动文件, 每次 -gen2 前从 embed 重新释放到
// System32\drivers(内容一致则跳过写入, 避免占用冲突)。返回 true = 驱动文件已就绪。

func redeployDriverFile(sysFile string) bool {
	data, err := embedded.ReadFile("embed/" + sysFile)
	if err != nil {
		return false
	}

	target := os.Getenv("SystemRoot") + "\\System32\\drivers\\" + sysFile
	if cur, cerr := os.ReadFile(target); cerr == nil && len(cur) == len(data) {
		return true
	}
	if werr := os.WriteFile(target, data, 0o644); werr != nil {
		return false
	}
	return true
}





func ensureSvcLoaded(name string, sysFile string) {
	if out, _ := hxcore.RunOut("sc.exe", "query", name); strings.Contains(out, "RUNNING") {
		return // 已运行
	}
	if redeployDriverFile(sysFile) {
		hxcore.AddDefenderExclusions()
	}
	bin := fmt.Sprintf("\\SystemRoot\\System32\\drivers\\%s", sysFile)
	hxcore.RunOut("sc.exe", "create", name, "type=", "kernel", "start=", "demand", "binPath=", bin)
	_, err := hxcore.RunOut("sc.exe", "start", name)
	if err != nil {
		// 首次启动失败 - 常见于杀软删除驱动文件或服务配置被改为 disabled。
		// 删除服务 -> 重新部署 -> 用新建服务重试一次。
		
		hxcore.RunOut("sc.exe", "delete", name)
		redeployDriverFile(sysFile)
		hxcore.RunOut("sc.exe", "create", name, "type=", "kernel", "start=", "demand", "binPath=", bin)
		if out, err := hxcore.RunOut("sc.exe", "start", name); err != nil {
			fmt.Printf("[Gen2] 启动服务 %s 失败: %s\n", name, strings.TrimSpace(out))
			if !isAdmin() {
				fmt.Println("[Gen2] 当前非管理员 — 交给 SYSTEM 计划任务处理(无需操作)")
			}
		}
	}
}

func setupBootEntry() error {
	// 幂等: 已存在 "50HX Unlock" 项则跳过 (用全量 firmware 枚举, 描述在项详情)
	if out, _ := hxcore.RunOut("bcdedit.exe", "/enum", "firmware"); strings.Contains(out, bootDesc) {
		fmt.Println("    启动项已存在, 跳过")
		return nil
	}
	// 1. copy {bootmgr} 作模板
	out, err := hxcore.RunOut("bcdedit.exe", "/copy", "{bootmgr}", "/d", bootDesc)
	if err != nil {
		return fmt.Errorf("bcdedit copy: %v", err)
	}
	re := regexp.MustCompile(`\{([0-9a-fA-F-]{36})\}`)
	m := re.FindStringSubmatch(out)
	if len(m) < 2 {
		return errors.New("无法解析 bcdedit 输出: " + out)
	}
	guid := m[1]
	cleanup := func() { hxcore.RunOut("bcdedit.exe", "/delete", "{"+guid+"}", "/f") }

	// 2. 找 ESP 盘符 (mountvol 重挂)
	esp := hxcore.MountESP()
	if esp == "" {
		cleanup()
		return errors.New("无法挂载 ESP")
	}
	defer hxcore.UnmountESP(esp)

	// 3. set device + path
	if _, err := hxcore.RunOut("bcdedit.exe", "/set", "{"+guid+"}", "device", "partition="+esp+":"); err != nil {
		cleanup()
		return err
	}
	path := efiDir + "\\" + efiFile // \EFI\50HX\50HXUNLK.EFI
	if _, err := hxcore.RunOut("bcdedit.exe", "/set", "{"+guid+"}", "path", path); err != nil {
		cleanup()
		return err
	}
	// 4. displayorder addfirst
	if _, err := hxcore.RunOut("bcdedit.exe", "/set", "{fwbootmgr}", "displayorder", "{"+guid+"}", "/addfirst"); err != nil {
		cleanup()
		return err
	}
	fmt.Printf("    启动项 %s 已置顶\n", guid)
	return nil
}

func setRunKey() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Println("  [!] 无法获取 exe 路径:", err)
		return
	}
	abs, _ := filepath.Abs(exe)
	val := fmt.Sprintf("\"%s\" -gen2 -silent", abs)
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err != nil {
		k, _, err = registry.CreateKey(registry.CURRENT_USER,
			`Software\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	}
	if err != nil {
		fmt.Println("  [!] Run 键写入失败:", err)
		return
	}
	defer k.Close()
	if err := k.SetStringValue("50HXGen2", val); err != nil {
		fmt.Println("  [!] Run 键设置失败:", err)
		return
	}
	// 注意: 这只是 HKCU Run 键(辅助通道, 登录瞬间先试); SYSTEM 计划任务才是权威通道。
	// 不要打印成"Gen2 已注册", 以免与下方 setupGen2Task 的成功提示混淆。
	fmt.Println("  Gen2 Run 键已写入(HKCU, 登录瞬间先试; SYSTEM 任务为权威通道): " + abs)
}

// setupGen2Task: v2.4.6 核心 — 注册 SYSTEM 计划任务, 登录时(延迟 30s)以
// 最高权限静默执行 -gen2。
//
// 为什么需要它: 驱动服务是 demand 启动, 登录后需 sc start 拉起, 而 sc start
// 需要管理员。Run 键以普通用户权限跑 → "OpenService 失败 5: 拒绝访问" →
// 驱动永远起不来 → Gen2 永远失败(社区 #1/#2 的真实根因)。
// 为什么不用 UAC 提权: 每次登录弹 UAC 体验差, 且 UAC 关闭时静默降权仍失败。
// SYSTEM 任务 = 无声的管理员: 权限最高、无弹窗、时机仍在登录后(安全)。
// 注意保持 demand: 若改 auto 会在开机早期加载驱动, 与 nvlddmkm 争用 BAR0
// (历史实测 code19 / 启动异常), demand + 登录后加载才是验证过的时序。
//
// v2.6.0: 改为返回 error; 创建后用 hxcore.TaskInfo 二次校验任务真的存在
// (此前 schtasks 返回成功即认为完成, 用户端"任务未注册"直到 Gen2 没跑才暴露),
// 失败自动重试; 仍失败返回错误, 由调用方弹窗给修复命令(-task)。
//
// v2.6.0 修复(社区"非管理员安装却提示未注册、重启又自动解锁"误报根因):
// schtasks /create 退出码 0 = 任务已提交给计划任务服务(真实成功)。
//
// 权威判据必须且只能是"退出码 0", 不能依赖其 stdout 中的 "SUCCESS/成功" 串:
//  · 中文 Windows 上 "成功" 由 schtasks 以系统 ANSI/GBK 代码页写出, 而 Go 把
//    管道字节当 UTF-8, 字面量 "成功"(UTF-8) 与 GBK 字节不匹配 -> Contains 失败;
//  · 部分环境 schtasks /create 的 stdout 甚至为空(成功信息走别处), 同样无串可匹配;
//  · 此前依赖 "SUCCESS/成功" 串 -> 串缺失即误判, 实测在中文机上稳定复现"假失败"。
// 退出码 0 = 任务已写入计划服务, 与语言/代码页无关, 是可靠判据。
// (紧随其后的 /query 仍存在提交延迟竞态, 仅作可选信息, 不再作为成败判据。)
func setupGen2Task() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("无法获取 exe 路径: %v", err)
	}
	abs, _ := filepath.Abs(exe)
	tn := gen2TaskName
	var lastErr string
	for attempt := 1; attempt <= 3; attempt++ {
		out, cerr := hxcore.RunOut("schtasks.exe", "/create", "/tn", tn,
			"/tr", fmt.Sprintf("\"%s\" -gen2 -silent -guard", abs),
			"/sc", "onlogon", "/ru", "SYSTEM", "/delay", "0000:30", "/f")
		// 权威判据 = 退出码 0。任务已写入计划服务(中文机上 SUCCESS/成功 串不可靠, 不依赖)。
		// 仅在退出码非 0 时才视为真实失败; 退出码 0 一律视为成功, 不再二次查询(避免提交延迟竞态误报)。
		if cerr == nil {
			fmt.Println("  Gen2 任务已注册(SYSTEM, 登录延迟30s, 静默): " + abs)
			return nil
		}
		lastErr = strings.TrimSpace(out)
		if attempt < 3 {
			fmt.Printf("  [!] 任务注册失败(第%d次), 重试... (%s)\n", attempt, lastErr)
			time.Sleep(800 * time.Millisecond)
		}
	}
	return fmt.Errorf("Gen2 计划任务创建失败(已重试): %s\n      可手动: 以管理员运行 50HXInstaller.exe -task", lastErr)
}

// ===================== Gen2 解锁 (原生, 无 python) =====================

func gen2Main() {
	// 幂等; -silent(登录自启动调用)时全程无窗口静默
	// v2.5: BYOVD (ThrottleStop + WinRing0) — 免测试签名; 用完即卸(自清理)

	// v2.6.0: 单实例互斥 — 防止 SYSTEM 任务 / Run 键 / 手动 -gen2 并发触发时,
	// 两进程同时 sc start 同一驱动、争抢 BAR0 导致链路/驱动状态错乱。
	// 放在最前: 拿不到锁直接退出, 绝不进入驱动加载临界区。
	owned, release := gen2AcquireSingleInstance()
	if !owned {
		fmt.Println("[Gen2] 另一 Gen2 实例正在运行, 跳过(单实例保护)")
		hxcore.WriteGen2Status("⏭️ 跳过: 另一 Gen2 实例正在运行(单实例保护, 避免并发抢驱动)")
		return
	}
	defer release()

	// v2.6.0: 时序保护 — 等 nvlddmkm 进入 RUNNING 后再动 GPU。抢在 nv 驱动初始化前
	// retrain 会被 nv 起来后重置 PCIe 链路 / 覆盖 GPU 寄存器, 既冲掉 Gen2, 又可能触发
	// code19(安装器注释 §785 已实证 "nvlddmkm 正占用 GPU 时 retrain 导致异常")。
	// 普通机器 nv 登录后几秒即 RUNNING → 此处几乎不等待; 慢速/多卡机器则等到就绪,
	// 避免与 nv 初始化重叠(固定 30s 延迟的脆弱性由此消除)。
	waitForNvDriver(60 * time.Second)

	ensureGspSilent()
	defer cleanupByovd() // 注册最早→最后执行(在句柄 Close 后), 失败也清理

	// 驱动文件可能被上次"用完即卸"删除, 每次从 embed 重新放好
	sysDir := os.Getenv("SystemRoot") + "\\System32\\drivers"
	for _, df := range []string{"ThrottleStop.sys", "WinRing0x64.sys"} {
		if _, err := os.Stat(filepath.Join(sysDir, df)); err != nil {
			copyEmbedTo(filepath.Join(sysDir, df), df) // 占用中忽略错误
		}
	}
	ensureSvcLoaded("ThrottleStop", "ThrottleStop.sys")
	ensureSvcLoaded("WinRing0_1_2_0", "WinRing0x64.sys")

	th, err := hxcore.OpenThrottleStop()
	if err != nil {
		if !isAdmin() {
			fmt.Println("[Gen2] ThrottleStop 未加载且当前非管理员 — 交给 SYSTEM 任务处理, 静默退出")
			gen2StatusFail("ThrottleStop 驱动未加载(由 SYSTEM 任务负责拉起)")
			return
		}
		fmt.Println("[Gen2] ThrottleStop 驱动未运行。请重跑安装器(管理员)后重启。")
		gen2StatusFail("ThrottleStop 驱动未运行 (需管理员重跑安装器)")
		gen2Notify("ThrottleStop 驱动未运行。\n可能原因: ①杀软隔离了 ThrottleStop.sys(本工具已加 Defender 排除, 第三方杀软请在安全中心放行); ②本机 ThrottleStop 软件占用/冲突(关闭 ThrottleStop 后重试, 本工具会自动复用)。\n请右键安装程序 -> 以管理员身份运行, 再重启。")
		return
	}
	// th/wh 句柄可能在 -hard 回退(Stage2)中被重开, 统一在下方 wh 处闭包按最终值关闭

	wh, err := hxcore.OpenDevice(`\\.\WinRing0_1_2_0`)
	if err != nil {
		if !isAdmin() {
			fmt.Println("[Gen2] WinRing0 未加载且当前非管理员 — 交给 SYSTEM 任务处理, 静默退出")
			gen2StatusFail("WinRing0 驱动未加载, 且当前为普通权限(由 SYSTEM 任务负责拉起)")
			return
		}
		fmt.Println("[Gen2] WinRing0 驱动未运行。")
		gen2StatusFail("WinRing0 驱动未运行 (需管理员重跑安装器)")
		gen2Notify("WinRing0 驱动未运行。\n可能原因: ①杀软隔离了 WinRing0x64.sys(本工具已加 Defender 排除, 第三方杀软请在安全中心放行); ②本机 ThrottleStop 软件占用/冲突(关闭 ThrottleStop 后重试, 本工具会自动复用)。\n请右键安装程序 -> 以管理员身份运行, 再重启。")
		return
	}
	// 闭包按最终值关闭 th/wh(支持 -hard 回退中重开驱动句柄)
	defer func() { hxcore.CloseHandle(th); hxcore.CloseHandle(wh) }()

	// 定位 50HX (VEN_10DE&DEV_1E09), 不硬编码 BDF
	// v2.6.0: 慢速 GPU 初始化(开机 50HX 未就绪)会偶发定位失败 → 重试最多 3 次,
	// 避免"假失败"导致本次开机不解锁(30s 后的 SYSTEM 任务会再确认一次)。
	var gpuBDF uint32
	gpuFound := false
	for attempt := 1; attempt <= 3; attempt++ {
		gpuBDF, gpuFound = hxcore.FindGPUPCI(wh)
		if gpuFound {
			break
		}
		if attempt < 3 {
			fmt.Printf("[Gen2] 暂未定位到 40HX, 2s 后重试 (%d/3)...\n", attempt)
			time.Sleep(2 * time.Second)
		}
	}
	if !gpuFound {
		fmt.Println("[Gen2] 未能定位 50HX (VEN_10DE&DEV_1E09)。请发日志。")
		gen2StatusFail("未能在 PCI 总线上定位 50HX (VEN_10DE&DEV_1E09)")
		gen2Notify("未能在 PCI 总线上找到 40HX。\n请确认显卡已插好且驱动已装。")
		return
	}
	gpuBus := (gpuBDF >> 8) & 0xFF
	fmt.Printf("[Gen2] 50HX 位于 %02x:%02x.%x\n", gpuBus, (gpuBDF>>3)&0x1F, gpuBDF&7)
	cur := hxcore.LinkSpeed(wh, gpuBDF)
	fmt.Printf("[Gen2] 当前链路: Gen%d\n", cur)
	// v2.6.0: 记录原始 PCIe 寄存器(LNKCAP/LNKCTL/LNKCTL2) — 社区反馈 -hard 调试用
	if cap := hxcore.PcieCap(wh, gpuBDF); cap != 0 {
		rd := func(off uint32) uint32 {
			v, _ := hxcore.PciRd(wh, gpuBDF, off)
			return v
		}
		fmt.Printf("[Gen2] LNKCAP=0x%08X LNKCTL=0x%08X LNKCTL2=0x%08X (目标Gen%d)\n",
			rd(cap+0x0C), rd(cap+0x10), rd(cap+0x30), rd(cap+0x30)&0xF)
	}
	if cur >= 2 {
		fmt.Println("[Gen2] 已是 Gen2, 无需操作。")
		hxcore.WriteGen2Status(fmt.Sprintf("✅ Gen2 无需操作: 当前链路已是 Gen%d\n运行身份: %s\n50HX 位置: %02x:%02x.%x\n",
			cur, map[bool]string{true: "管理员/SYSTEM", false: "普通用户(受限)"}[isAdmin()],
			gpuBus, (gpuBDF>>3)&0x1F, gpuBDF&7))
		gen2Notify("PCIe 已是 Gen" + fmt.Sprint(cur) + ", 无需操作。")
		return
	}

	// 1. PL0 writes (BAR0) — 经 ThrottleStop 物理内存写
	fmt.Println("[Gen2] 写 XVE/链路寄存器 (ThrottleStop)...")
	pl0 := []struct {
		off  uint64
		val  uint32
		name string
	}{
		{0x8872C, 0x6, "XVE_OVR=6"},
		{0x8C040, 0x80085800, "LINK_CONFIG_0"},
		{0x8841C, 0xE0B42D00, "PRIV_MISC_1"},
		{0x8C2C0, 0x068731B3, "CYA_0"},
	}
	bar0raw, _ := hxcore.PciRd(wh, gpuBDF, 0x10)
	if bar0raw == 0 || bar0raw == 0xFFFFFFFF {
		bar0raw = 0xF6000000
	}
	bar0Phys := uint64(bar0raw & 0xFFFFFFF0)
	fmt.Printf("[Gen2] BAR0 = 0x%08X\n", bar0Phys)
	// v2.6.0: BAR0 合法性校验 — 写 PL0 前确认 BAR0 真指向 50HX MMIO, 避免把 4 个
	// 链路寄存器写到错误物理地址(多卡/寨板 BAR 重映射、BAR0 读回异常场景)。
	// NV_PMC BOOT_0 @ BAR0+0x0: TU106 家族字节 = 0x16 (unlock40x_v70.c:2555 记 40HX=0x166000A1)。
	// 家族不匹配或读回 0xFFFFFFFF → 中止 PL0 写入(宁可本次不开锁, 不污染他设备 MMIO)。
	boot0, berr := hxcore.TSRead(th, bar0Phys+0x0)
	if berr != nil || (boot0&0xFF000000) != 0x16000000 {
		fmt.Printf("[Gen2][!] BAR0 合法性校验失败: BOOT_0=0x%08X (期望 TU10x 家族 0x16xxxxxx), 中止 PL0 写入\n", boot0)
		gen2StatusFail(fmt.Sprintf("BAR0 校验失败(BOOT_0=0x%08X), 安全中止 PL0 写入; 请发日志", boot0))
		if !hasArg("-silent") {
			gen2Notify("BAR0 校验失败, Gen2 安全中止。\n请发日志。")
		}
		return
	}
	fmt.Printf("[Gen2] BAR0 校验通过 (BOOT_0=0x%08X, TU106)\n", boot0)
	for _, p := range pl0 {
		if werr := hxcore.TSWrite(th, bar0Phys+p.off, p.val); werr != nil {
			fmt.Printf("  [!] %s 写失败: %v\n", p.name, werr)
			continue
		}
		if rb, rerr := hxcore.TSRead(th, bar0Phys+p.off); rerr != nil || rb != p.val {
			fmt.Printf("  [warn] %s 读回 0x%08x (期望 0x%08x)\n", p.name, rb, p.val)
		} else {
			fmt.Printf("  %s OK (0x%08X)\n", p.name, rb)
		}
	}

	// 2. LNKCTL2 TLS=2 (GPU + root)
	root := hxcore.FindRootPort(wh, gpuBus)
	if root == 0xFFFFFFFF {
		fmt.Println("[Gen2] 未找到 root port, 用 GPU retrain fallback")
	}
	fmt.Printf("[Gen2] root port = 00:%02x.%x\n", (root>>3)&0x1F, root&7)
	for _, b := range []struct {
		bdf uint32
		tag string
	}{{gpuBDF, "GPU"}, {root, "ROOT"}} {
		if b.bdf == 0xFFFFFFFF {
			continue
		}
		cap := hxcore.PcieCap(wh, b.bdf)
		if cap == 0 {
			continue
		}
		// v2.6.0: 读改写 — 只改 TLS(bit3:0), 保留其余位(对齐 python 版)。
		// 此前直接写 {2,0} 清掉高 12 位, 个别 VBIOS 依赖这些位时链路异常。
		curRaw, _ := hxcore.PciRd(wh, b.bdf, cap+0x30)
		nv := uint16(curRaw&0xFFF0) | 2
		hxcore.PciWr(wh, b.bdf, cap+0x30, []byte{byte(nv), byte(nv >> 8)})
		rb, _ := hxcore.PciRd(wh, b.bdf, cap+0x30)
		fmt.Printf("  %s LNKCTL2 TLS=2 (0x%04X -> 0x%04X, 回读 TLS=%d)\n", b.tag, curRaw&0xFFFF, rb&0xFFFF, rb&0xF)
	}

	// 3. UPGRADE retrain: 清位→置位脉冲 (只置位在 50HX 上不生效)
	retrain := func(bdf uint32) {
		cap := hxcore.PcieCap(wh, bdf)
		if cap == 0 {
			return
		}
		ctl, _ := hxcore.PciRd(wh, bdf, cap+0x10)
		lo := uint16(ctl & 0xFFFF)
		buf := []byte{byte(lo & 0xFF), byte((lo >> 8) & 0xFF)}
		buf[0] &^= 0x20 // clear bit5
		hxcore.PciWr(wh, bdf, cap+0x10, buf)
		time.Sleep(300 * time.Millisecond)
		ctl2, _ := hxcore.PciRd(wh, bdf, cap+0x10)
		lo2 := uint16(ctl2 & 0xFFFF)
		buf2 := []byte{byte(lo2 & 0xFF), byte((lo2 >> 8) & 0xFF)}
		buf2[0] |= 0x20 // set bit5
		hxcore.PciWr(wh, bdf, cap+0x10, buf2)
	}
	// v2.6.0: 单次 root 重训 → 最多 6 轮 root/GPU 交替(对齐 python 版, 比初版 4 轮更稳)。
	// 寨板/双卡下根端口一次脉冲常训不上(issue #8 "需反复禁用/启用"),
	// 交替多轮显著提高成功率; 达成 Gen2 即提前退出(上限约 13s, 登录后 30s 才跑)。
	for attempt := 0; attempt < 6; attempt++ {
		bdf, tag := gpuBDF, "GPU"
		if attempt%2 == 0 && root != 0xFFFFFFFF {
			bdf, tag = root, "ROOT"
		}
		fmt.Printf("[Gen2] 链路重训 #%d (%s端)...\n", attempt+1, tag)
		retrain(bdf)
		time.Sleep(2200 * time.Millisecond)
		cur = hxcore.LinkSpeed(wh, gpuBDF)
		if cur >= 2 {
			break
		}
	}

	// v2.6.0: 判据修正 — 驱动/ASPM 会在空闲时把链路降到 Gen1 省电, 只看当前
	// 速率会把成功误报成失败(社区"Gen1"误报来源之一, v2.4.5 时代已实证:
	// "待机省电时为 Gen1, 负载下自动跑满 Gen2")。以 GPU LNKCTL2 的
	// TLS(目标速率)区分: TLS>=2 且当前 Gen1 = 配置成功, 空闲降速属正常。
	tls := uint32(0)
	if gcap := hxcore.PcieCap(wh, gpuBDF); gcap != 0 {
		if v, rerr := hxcore.PciRd(wh, gpuBDF, gcap+0x30); rerr == nil {
			tls = v & 0xF
		}
	}
	// v2.5.2: Stage2 自动化(社区 #11/#20/#8 + 贴吧多平台复现的实证解法) —
	// 寨板/多卡/X99 平台 retrain-only 开机训不上, 需要 Root Link Disable(+
	// PnP 恢复)才能上 Gen2, 且每次开机都得重来一次(#20 实证); 手动 -hard
	// 用户根本不会做, 贴吧/B站大量"每开机手动禁用启用显卡"的变通皆源于此。
	// 现在登录任务在 Stage1 未达成(cur<2)时自动执行一次 Stage2(静默, 上限约1分钟):
	//   · 无论 TLS: TLS 已配而链路仍 Gen1 → LD 会立即训上并消除"空闲降速"歧义;
	//     TLS 没配上 → LD 后重写常能粘住(贴吧 .06 批次用户 LD 后同样成功,
	//     说明"写保护批次"与"retrain-only 不够"此前被混为一谈)。
	//   · 退出开关: reg add HKLM\SOFTWARE\50HXUnlock /v Gen2AutoHard /t REG_DWORD /d 0 /f
	//     (50HX 是唯一显示卡的机器若不想要登录后数秒黑屏, 可关)
	//   · 手动 -hard 保留: cur<2 即强制走该路径(不再要求 tls>=2)。
	// Link Disable 期间 nvidia-smi 短暂报 "GPU is lost", 结束后自动 PnP 恢复。
	if cur < 2 && (hasArg("-hard") || gen2AutoHardEnabled()) {
		if hasArg("-hard") {
			fmt.Println("[Gen2] retrain 未成 → -hard 显式触发 Link Disable 回退")
		} else {
			fmt.Println("[Gen2] retrain 未成 → 自动执行 Link Disable 回退 (Gen2AutoHard 默认开; 关闭方法见 README §2.5)")
		}
		gen2HardFallback(&th, &wh, gpuBDF, bar0Phys, root)
		return
	}
	gen2Verdict := ""
	unlocked := false
	switch {
	case cur >= 2:
		unlocked = true
		fmt.Printf("[Gen2] *** GEN2 ACHIEVED (Gen%d) ***\n", cur)
		gen2Verdict = fmt.Sprintf("✅ Gen2 成功: 当前链路 Gen%d", cur)
	case tls >= 2:
		unlocked = true
		fmt.Printf("[Gen2] TLS=Gen%d 但当前 Gen%d — 空闲省电降速(负载下自动回 Gen2)\n", tls, cur)
		gen2Verdict = fmt.Sprintf("🟢 Gen2 已配置(TLS=Gen%d): 当前 Gen%d 为空闲省电降速, 负载下自动回 Gen2", tls, cur)
	default:
		fmt.Printf("[Gen2] 仍在 Gen%d (TLS=Gen%d), 解锁失败。请发日志。\n", cur, tls)
		gen2Verdict = fmt.Sprintf("❌ Gen2 失败: 仍在 Gen%d (TLS=Gen%d; PL0 全 OK 而 TLS 未粘住, 多为驱动/GSP 持有链路策略 — 登录任务(已注册)会自动执行 Stage2 回退; 任务未注册则不会自动跑, 先注册再重试; 详见 README §5.2)", cur, tls)
	}
	// v2.6.0: 成功清掉遗留重试任务; 失败按策略安排自动重试(次数/间隔见 hxcore config)。
	// v3.0.1: 常驻守护模式不排一次性重试任务 — 守护进程每分钟自行重试。
	if unlocked {
		deleteGen2Retry()
	} else if hxcore.DriverStrategy() != hxcore.DriverStrategyResident {
		scheduleGen2Retry(retryDepth())
	}
	st := fmt.Sprintf("结论: %s\n运行身份: %s\n50HX 位置: %02x:%02x.%x\nRoot Port: %02x:%02x.%x\n"+
		"链路: 当前 Gen%d / 目标 TLS=Gen%d\n驱动: ThrottleStop=✓ WinRing0=✓ (BYOVD, 用完即卸)\n",
		gen2Verdict,
		map[bool]string{true: "管理员/SYSTEM", false: "普通用户(受限)"}[isAdmin()],
		gpuBus, (gpuBDF>>3)&0x1F, gpuBDF&7,
		(root>>8)&0xFF, (root>>3)&0x1F, root&7,
		cur, tls)
	if wErr := hxcore.WriteGen2Status(st); wErr != nil {
		fmt.Printf("[Gen2] 状态文件写入失败(不影响解锁): %v\n", wErr)
	}
	if !hasArg("-silent") && !hasArg("-y") {
		icon := uint(mbIconInfo)
		txt := fmt.Sprintf("PCIe 链路: 当前 Gen%d (目标 TLS=Gen%d)\n", cur, tls)
		if unlocked {
			txt += "=== GEN2 解锁成功 ==="
			if cur < 2 {
				txt += "\n(当前为空闲省电降速, 负载下自动回 Gen2)"
			}
		} else {
			txt += "仍在 Gen1, 解锁失败(详见日志)。"
			icon = mbIconError
		}
		msgbox("50HX Gen2", txt, icon)
	}
}

// ---------- v3.0.1: 常驻守护 (驱动策略=常驻时, 由登录任务 -guard 启动) ----------
// 每 1 分钟读 GPU 目标速率 TLS: TLS>=2 就不动(空闲降 Gen1 属正常省电);
// TLS 掉回 <2 = 解锁配置丢失(如显卡复位/驱动重载) → 自动重跑一次完整解锁。
// 进程随登录任务常驻; 注销/任务结束/卸载即停止。守护重试不排一次性重试任务。
const gen2GuardInterval = 1 * time.Minute

func residentGuard() {
	fmt.Println("[守护] 常驻守护启动: 每 1 分钟检查 Gen2 目标(TLS), 配置丢失(TLS<2)自动重训; 注销或任务结束即停止。")
	for {
		time.Sleep(gen2GuardInterval)
		st := hxcore.ReadUnlockStateV2(0, 0)
		if st.TLS >= 2 {
			continue // 目标仍在: 空闲降速属正常, 不动
		}
		fmt.Println("[守护] 检测到 TLS<2 — Gen2 解锁配置丢失, 自动重新解锁...")
		gen2Main()
	}
}

// ---------- Gen2 -hard 回退: Root Link Disable + PnP 恢复 (Stage 2) ----------
// 仅当显式 50HXInstaller.exe -gen2 -hard 时进入。普通/计划任务路径绝不触发,
// 因为 Root Link Disable 会让 nvidia-smi 短暂报 "GPU is lost"(链路瞬断+驱动重置)。
// 对齐社区 byovd.py(member573, issue #11, 2026-09-06 多卡实测):
//   retrain-only 在寨板/多卡不足 → Root Link Disable 循环(PL0+TLS 保持)使
//   LNKCAP.max=2 训上 Gen2 → PnP 禁用/启用 50HX 恢复 "GPU is lost" →
//   Retrain-ONLY(不再二次 LD, 保驱动健康) → 重启 NVDisplay.ContainerLocalSystem。
// 代码层无法判断"当前 Gen1 是空闲降速还是真训不上", 故 -hard 交给用户手动裁决。

func gen2WritePL0(th syscall.Handle, bar0Phys uint64) {
	pl0 := []struct {
		off  uint64
		val  uint32
		name string
	}{
		{0x8872C, 0x6, "XVE_OVR=6"},
		{0x8C040, 0x80085800, "LINK_CONFIG_0"},
		{0x8841C, 0xE0B42D00, "PRIV_MISC_1"},
		{0x8C2C0, 0x068731B3, "CYA_0"},
	}
	for _, p := range pl0 {
		if werr := hxcore.TSWrite(th, bar0Phys+p.off, p.val); werr != nil {
			fmt.Printf("  [!] %s 写失败: %v\n", p.name, werr)
			continue
		}
		if rb, rerr := hxcore.TSRead(th, bar0Phys+p.off); rerr != nil || rb != p.val {
			fmt.Printf("  [warn] %s 读回 0x%08x (期望 0x%08x)\n", p.name, rb, p.val)
		} else {
			fmt.Printf("  %s OK (0x%08X)\n", p.name, rb)
		}
	}
}

// 16-bit LNKCTL2 写 TLS(只读改写 bit3:0, 保留其余位)
func gen2SetTLS(wh syscall.Handle, bdf uint32, tls uint16) {
	if bdf == 0xFFFFFFFF {
		return
	}
	cap := hxcore.PcieCap(wh, bdf)
	if cap == 0 {
		return
	}
	cur, _ := hxcore.PciRd(wh, bdf, cap+0x30)
	nv := uint16(cur&0xFFF0) | (tls & 0xF)
	_ = hxcore.PciWr(wh, bdf, cap+0x30, []byte{byte(nv), byte(nv >> 8)})
	rb, _ := hxcore.PciRd(wh, bdf, cap+0x30)
	fmt.Printf("    TLS=%d 写 LNKCTL2 (0x%04X -> 0x%04X, 回读 TLS=%d)\n", tls, cur&0xFFFF, rb&0xFFFF, rb&0xF)
}

// 16-bit LNKCTL 脉冲 retrain(bit5)
func gen2RetrainPulse(wh syscall.Handle, bdf uint32) {
	if bdf == 0xFFFFFFFF {
		return
	}
	cap := hxcore.PcieCap(wh, bdf)
	if cap == 0 {
		return
	}
	ctl, _ := hxcore.PciRd(wh, bdf, cap+0x10)
	lo := uint16(ctl & 0xFFFF)
	buf := []byte{byte(lo & 0xFF), byte((lo >> 8) & 0xFF)}
	buf[0] &^= 0x20 // clear bit5
	_ = hxcore.PciWr(wh, bdf, cap+0x10, buf)
	time.Sleep(300 * time.Millisecond)
	ctl2, _ := hxcore.PciRd(wh, bdf, cap+0x10)
	lo2 := uint16(ctl2 & 0xFFFF)
	buf2 := []byte{byte(lo2 & 0xFF), byte((lo2 >> 8) & 0xFF)}
	buf2[0] |= 0x20 // set bit5
	_ = hxcore.PciWr(wh, bdf, cap+0x10, buf2)
}

// Root Link Disable 循环(PL0+TLS 保持) — 使 LNKCAP.max=2 训上 Gen2
func gen2RootLinkDisable(th syscall.Handle, wh *syscall.Handle, gpuBDF uint32, bar0Phys uint64, root uint32) {
	if root == 0xFFFFFFFF {
		fmt.Println("    [warn] 无 root port, 跳过 Link Disable")
		return
	}
	cap := hxcore.PcieCap(*wh, root)
	if cap == 0 {
		fmt.Println("    [warn] root 无 PCIe cap, 跳过 Link Disable")
		return
	}
	ctl, _ := hxcore.PciRd(*wh, root, cap+0x10)
	fmt.Printf("    ROOT Link Disable (ctl=0x%04X)\n", ctl&0xFFFF)
	lo := uint16(ctl & 0xFFFF)
	set := lo | 0x10 // bit4 = Link Disable
	_ = hxcore.PciWr(*wh, root, cap+0x10, []byte{byte(set), byte(set >> 8)})
	time.Sleep(500 * time.Millisecond)
	// PL0 + TLS 在 link down 期间保持
	gen2WritePL0(th, bar0Phys)
	gen2SetTLS(*wh, root, 2)
	gen2SetTLS(*wh, gpuBDF, 2)
	// clear bit4 → 重新训练
	ctl2, _ := hxcore.PciRd(*wh, root, cap+0x10)
	clr := uint16(ctl2&0xFFFF) &^ 0x10
	_ = hxcore.PciWr(*wh, root, cap+0x10, []byte{byte(clr), byte(clr >> 8)})
	time.Sleep(2000 * time.Millisecond)
}

// PnP 禁用/启用 50HX — 恢复 Link Disable 后的 "GPU is lost"(nvidia-smi/GPU-Z 断连)
func gen2PnpRecover40HX() bool {
	ps := `$iid=(Get-PnpDevice -Class Display | Where-Object { $_.InstanceId -match 'DEV_1E09' } | Select-Object -First 1).InstanceId; ` +
		`if($iid){ Disable-PnpDevice -InstanceId $iid -Confirm:$false; Start-Sleep -Seconds 2; ` +
		`Enable-PnpDevice -InstanceId $iid -Confirm:$false; Start-Sleep -Seconds 4; Write-Output "PnP-OK $iid" } ` +
		`else { Write-Output 'PnP-NONE' }`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
	fmt.Printf("    PnP 恢复: %s (err=%v)\n", strings.TrimSpace(string(out)), err)
	return err == nil && strings.Contains(string(out), "PnP-OK")
}

// 重启 NVDisplay 容器(恢复 GPU-Z / 任务管理器的显示, Link Disable 后常需)
func gen2RestartNVDisplay() {
	ps := `Restart-Service NVDisplay.ContainerLocalSystem -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2`
	out, err := exec.Command("powershell", "-NoProfile", "-Command", ps).CombinedOutput()
	fmt.Printf("    NVDisplay 容器重启: %s (err=%v)\n", strings.TrimSpace(string(out)), err)
}

// -hard 回退中 PnP 导致 GPU reset, 旧 \\.\ThrottleStop / WinRing0 句柄可能失效 → 重开
func gen2ReopenDrivers(th, wh *syscall.Handle) bool {
	hxcore.CloseHandle(*th)
	hxcore.CloseHandle(*wh)
	ok := true
	if nt, e := hxcore.OpenThrottleStop(); e != nil {
		fmt.Printf("    [!] ThrottleStop 重开失败: %v\n", e)
		ok = false
	} else {
		*th = nt
	}
	if nw, e := hxcore.OpenDevice(`\\.\WinRing0_1_2_0`); e != nil {
		fmt.Printf("    [!] WinRing0 重开失败: %v\n", e)
		ok = false
	} else {
		*wh = nw
	}
	return ok
}

// 恢复 GPU LNKCTL CCC(0x0140, Common Clock + Extended Synch) — 保 NVAPI/GPU-Z 健康
func gen2RestoreGPULnkctl(wh syscall.Handle, gpuBDF uint32) {
	cap := hxcore.PcieCap(wh, gpuBDF)
	if cap == 0 {
		return
	}
	ctl, _ := hxcore.PciRd(wh, gpuBDF, cap+0x10)
	cur := uint16(ctl & 0xFFFF)
	if (cur & 0x0140) != 0x0140 {
		want := (cur &^ 0x3) | 0x0140
		_ = hxcore.PciWr(wh, gpuBDF, cap+0x10, []byte{byte(want), byte(want >> 8)})
		rb, _ := hxcore.PciRd(wh, gpuBDF, cap+0x10)
		fmt.Printf("    GPU LNKCTL 恢复 0x%04X -> 0x%04X\n", cur, rb&0xFFFF)
	}
}

// Stage2 编排: LD → retrain → PnP 恢复 → retrain-only → NVDisplay 重启。自行写结论。
func gen2HardFallback(th, wh *syscall.Handle, gpuBDF uint32, bar0Phys uint64, root uint32) {
	fmt.Println("\n[Gen2 -hard] === Link Disable 回退路径 (Stage 2) ===")
	fmt.Println("[Gen2 -hard] 警告: 此路径会让 nvidia-smi 短暂报 'GPU is lost'(链路瞬断+驱动重置),")
	fmt.Println("[Gen2 -hard] 约数秒后经 PnP 恢复。仅在你确认 retrain-only 在贵硬件训不上时手动使用。")
	// 链路重置后 BAR 可能重映射 → 重新确认 BAR0
	if bar0raw, _ := hxcore.PciRd(*wh, gpuBDF, 0x10); bar0raw != 0 && bar0raw != 0xFFFFFFFF {
		bar0Phys = uint64(bar0raw & 0xFFFFFFF0)
	}
	fmt.Printf("[Gen2 -hard] BAR0 = 0x%08X\n", bar0Phys)
	didLD := false
	// 1. re-assert PL0
	gen2WritePL0(*th, bar0Phys)
	// 2. Root Link Disable 循环
	if root != 0xFFFFFFFF {
		gen2RootLinkDisable(*th, wh, gpuBDF, bar0Phys, root)
		didLD = true
	}
	cur := hxcore.LinkSpeed(*wh, gpuBDF)
	fmt.Printf("[Gen2 -hard] Link Disable 后: Gen%d\n", cur)
	// 3. 仍 Gen1 → retrain 脉冲(交替) 最多 6 轮
	if cur < 2 {
		for i := 0; i < 6; i++ {
			// 社区 byovd.py: retrain 第 3 轮(attempts==2)仍 Gen1 再走一次 Link Disable 循环
			if i == 2 && cur < 2 && root != 0xFFFFFFFF {
				fmt.Println("[Gen2 -hard] retrain 仍失败 → 二次 Link Disable 循环")
				gen2RootLinkDisable(*th, wh, gpuBDF, bar0Phys, root)
			}
			gen2WritePL0(*th, bar0Phys)
			gen2SetTLS(*wh, root, 2)
			gen2SetTLS(*wh, gpuBDF, 2)
			bdf := gpuBDF
			tag := "GPU"
			if root != 0xFFFFFFFF && i%2 == 0 {
				bdf, tag = root, "ROOT"
			}
			fmt.Printf("[Gen2 -hard] retrain #%d (%s)...\n", i+1, tag)
			gen2RetrainPulse(*wh, bdf)
			time.Sleep(2200 * time.Millisecond)
			cur = hxcore.LinkSpeed(*wh, gpuBDF)
			if cur >= 2 {
				break
			}
		}
	}
	// 4. PnP 恢复 "GPU is lost" + retrain-only + NVDisplay 重启
	// v2.6.0: 只要做过 Link Disable 就无条件恢复(此前仅成功时恢复 —
	// 失败时 GPU 悬在 lost 态, 用户只能设备管理器手动禁用/启用, 社区抱怨来源之一)
	if didLD {
		if cur >= 2 {
			fmt.Println("[Gen2 -hard] 已训上 Gen2, 执行 PnP 恢复 + NVDisplay 重启")
		} else {
			fmt.Println("[Gen2 -hard] 训练未成, 仍执行 PnP 恢复确保 GPU 回到正常状态")
		}
		gen2PnpRecover40HX()
		if !gen2ReopenDrivers(th, wh) {
			fmt.Println("[Gen2 -hard][!] 驱动重开失败, 中止后续恢复")
			gen2VerdictHard(gpuBDF, cur, false)
			return
		}
		time.Sleep(3000 * time.Millisecond)
		// retrain-only(不再二次 LD)
		if bar0raw, _ := hxcore.PciRd(*wh, gpuBDF, 0x10); bar0raw != 0 && bar0raw != 0xFFFFFFFF {
			bar0Phys = uint64(bar0raw & 0xFFFFFFF0)
		}
		gen2WritePL0(*th, bar0Phys)
		gen2SetTLS(*wh, root, 2)
		gen2SetTLS(*wh, gpuBDF, 2)
		for i := 0; i < 6; i++ {
			cur = hxcore.LinkSpeed(*wh, gpuBDF)
			if cur >= 2 {
				break
			}
			bdf := gpuBDF
			if root != 0xFFFFFFFF && i%2 == 0 {
				bdf = root
			}
			gen2RetrainPulse(*wh, bdf)
			time.Sleep(2200 * time.Millisecond)
		}
		gen2RestoreGPULnkctl(*wh, gpuBDF)
		gen2RestartNVDisplay()
		cur = hxcore.LinkSpeed(*wh, gpuBDF)
		fmt.Printf("[Gen2 -hard] PnP 恢复后: Gen%d\n", cur)
	}
	gen2VerdictHard(gpuBDF, cur, cur >= 2)
}

func gen2VerdictHard(gpuBDF uint32, cur uint32, success bool) {
	// v2.6.0: 与 Stage1 verdict 同一套重试策略 — 成功清重试任务, 失败按预算再排
	if success {
		deleteGen2Retry()
	} else {
		scheduleGen2Retry(retryDepth())
	}
	gpuBus := (gpuBDF >> 8) & 0xFF
	st := fmt.Sprintf("结论(Link Disable 回退): %s\n50HX 位置: %02x:%02x.%x\n链路: 当前 Gen%d\n驱动: ThrottleStop=✓ WinRing0=✓ (BYOVD, 按策略收尾)\n",
		map[bool]string{true: "✅ Gen2 成功", false: "❌ Gen2 失败(见日志/发社区)"}[success],
		gpuBus, (gpuBDF>>3)&0x1F, gpuBDF&7, cur)
	if wErr := hxcore.WriteGen2Status(st); wErr != nil {
		fmt.Printf("[Gen2 -hard] 状态写入失败: %v\n", wErr)
	}
	if !hasArg("-silent") && !hasArg("-y") {
		icon := uint(mbIconInfo)
		txt := fmt.Sprintf("Gen2 回退: 当前 Gen%d\n", cur)
		if success {
			txt += "=== GEN2 解锁成功 ==="
		} else {
			txt += "仍在 Gen1, 回退未成(详见日志)。"
			icon = mbIconError
		}
		msgbox("50HX Gen2", txt, icon)
	}
}

// ---------- v2.6.0: Gen2 自动重试 + Stage2 自动回退开关 + 策略配置 ----------

// retryDepth: 当前自动重试深度(-retrydepth=N, 0=登录任务首次执行)
func retryDepth() int {
	for _, a := range os.Args {
		if strings.HasPrefix(a, "-retrydepth=") {
			if n, err := strconv.Atoi(strings.TrimPrefix(a, "-retrydepth=")); err == nil && n > 0 {
				return n
			}
		}
	}
	return 0
}

// gen2AutoHardEnabled: Stage2(Link Disable + PnP 恢复)自动执行开关, 默认开。
// 关闭: reg add HKLM\SOFTWARE\50HXUnlock /v Gen2AutoHard /t REG_DWORD /d 0 /f
// (50HX 是唯一显示卡、不希望登录后链路瞬断数秒黑屏的用户可关)
func gen2AutoHardEnabled() bool {
	return hxcore.ConfigInt("Gen2AutoHard", 1) != 0
}

// scheduleGen2Retry: 失败后安排一次性自动重试(SYSTEM, 静默, 默认 15 分钟后)。
// 覆盖"开机后驱动/GSP 就绪慢""链路状态恰好卡住"等时序类失败(社区 #12);
// depth 为已重试次数, 超出策略预算(Gen2RetryCount)即不再排; 成功路径 deleteGen2Retry。
func scheduleGen2Retry(depth int) {
	count, interval := hxcore.Gen2RetryPolicy()
	if depth >= count {
		fmt.Printf("[Gen2] 自动重试预算已用完(%d/%d), 等下次登录再试\n", depth, count)
		return
	}
	t := time.Now().Add(time.Duration(interval) * time.Minute)
	if t.Day() != time.Now().Day() {
		fmt.Println("[Gen2] 接近零点, 跳过本次重试排程(once 任务跨日期不可靠)")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	abs, _ := filepath.Abs(exe)
	out, err := hxcore.RunOut("schtasks.exe", "/create", "/tn", gen2RetryTask,
		"/tr", fmt.Sprintf("\"%s\" -gen2 -silent -retrydepth=%d", abs, depth+1),
		"/sc", "once", "/st", t.Format("15:04"), "/ru", "SYSTEM", "/f")
	if err != nil {
		fmt.Printf("[Gen2] 重试任务创建失败(不影响解锁): %s\n", strings.TrimSpace(out))
		return
	}
	fmt.Printf("[Gen2] 已安排 %d 分钟后自动重试(%d/%d, 任务 %s)\n", interval, depth+1, count, gen2RetryTask)
}

// deleteGen2Retry: Gen2 达成后清掉可能存在的重试任务
func deleteGen2Retry() {
	hxcore.RunOut("schtasks.exe", "/delete", "/tn", gen2RetryTask, "/f")
}

// gen2AcquireSingleInstance: v2.6.0 单实例保护。
// 返回 (是否取得独占, 释放函数)。未取得 = 已有别的实例在跑, 调用方应直接退出。
// 用内核全局互斥体 Global\50HXGen2SingleInstance: 跨用户/会话可见, 进程崩溃内核自动
// 释放, 比文件锁更可靠(文件锁挡不住两个进程同时 sc start 同一服务名)。
func gen2AcquireSingleInstance() (bool, func()) {
	name, _ := windows.UTF16PtrFromString("Global\\50HXGen2SingleInstance")
	h, err := windows.CreateMutex(nil, true, name)
	if err != nil {
		// 拿不到互斥体 → 放行(宁可多跑一次, 不漏解锁)
		fmt.Println("[Gen2] 单实例互斥体创建失败, 放行:", err)
		return true, func() {}
	}
	if windows.GetLastError() == windows.ERROR_ALREADY_EXISTS {
		_ = windows.CloseHandle(windows.Handle(h))
		return false, nil
	}
	return true, func() {
		_ = windows.ReleaseMutex(windows.Handle(h))
		_ = windows.CloseHandle(windows.Handle(h))
	}
}

// waitForNvDriver: v2.6.0 时序保护 — 必须等 nvlddmkm 真正 RUNNING 后再动 GPU。
// 抢在 nv 驱动初始化前 retrain 会被 nv 起来后重置 PCIe 链路 / 覆盖 GPU 寄存器,
// 既冲掉 Gen2, 又可能触发 code19(安装器注释 §785 已实证)。服务不存在(nv 未装)则
// 直接放行; 超时(60s)仍继续, 不阻塞解锁。
func waitForNvDriver(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		out, _ := hxcore.RunOut("sc.exe", "query", "nvlddmkm")
		if strings.Contains(out, "does not exist") || strings.Contains(out, "未安装") ||
			strings.Contains(out, "1060") {
			fmt.Println("[Gen2] 未检测到 nvlddmkm 服务, 跳过等待直接解锁")
			return true
		}
		if strings.Contains(out, "RUNNING") {
			return true
		}
		if time.Now().After(deadline) {
			fmt.Printf("[Gen2] nvlddmkm 在 %s 内未进入 RUNNING(详见日志), 仍继续解锁\n", timeout)
			return false
		}
		fmt.Println("[Gen2] 等待 nvlddmkm 就绪...")
		time.Sleep(2 * time.Second)
	}
}

// cleanupByovd: v2.5 用完即卸 — 停止并删除 ThrottleStop/WinRing0 服务与驱动文件。
// 在 gen2Main 末尾(defers)执行, 游戏时系统无第三方驱动残留。
// v2.6.0: 尊重驱动运行策略 — 常驻策略保留服务与文件(GUI 有反作弊风险提示)。
func cleanupByovd() {
	if hxcore.DriverStrategy() == hxcore.DriverStrategyResident {
		fmt.Println("[Gen2] 常驻策略: 保留驱动服务与文件(GUI/卸载器可移除)")
		return
	}
	appRunning := throttleStopAppRunning()
	for _, d := range []struct{ name, file string }{
		{"ThrottleStop", "ThrottleStop.sys"},
		{"WinRing0_1_2_0", "WinRing0x64.sys"},
	} {
		// 本机 ThrottleStop 软件正在用该驱动 → 不删(避免打断用户软件);
		// 否则保持"用完即卸": 停服务 + 删服务 + 删文件 → 内核无驻留、磁盘无残留,
		// 反作弊(尤其 Vanguard 类的磁盘扫描)不会在游戏时扫到 vulnerable 驱动。
		if appRunning {
			continue
		}
		hxcore.RunOut("sc.exe", "stop", d.name)
		hxcore.RunOut("sc.exe", "delete", d.name)
		os.Remove(filepath.Join(os.Getenv("SystemRoot")+"\\System32\\drivers", d.file))
	}
}

// gen2Notify: 失败提示; 静默模式不弹框
func gen2Notify(txt string) {
	if !hasArg("-silent") && !hasArg("-y") {
		msgbox("50HX Gen2", txt, mbIconError)
	}
}

// gen2StatusFail: v2.4.6 — 把 Gen2 未执行/失败的原因写入状态文件,
// 供 40HXCheck 展示(SYSTEM 任务在 Session 0 无法弹窗给用户看)。
func gen2StatusFail(reason string) {
	ident := map[bool]string{true: "管理员/SYSTEM", false: "普通用户(受限)"}[isAdmin()]
	hxcore.WriteGen2Status("❌ Gen2 未执行: " + reason + "\n运行身份: " + ident + "\n")
}

// ===================== 卸载/状态 =====================

func uninstall() {
	if !isAdmin() {
		fmt.Println("[!] 需要管理员权限。")
		msgbox("50HX 安装器", "需要管理员权限。\n请右键本程序 -> 以管理员身份运行。", mbIconError)
		return
	}
	if lockOnce(`Local\40HXUninstaller_v1`) == nil {
		msgbox("50HX 安装器", "卸载程序已在运行, 请勿重复点击。", mbIconInfo)
		return
	}
	// v2.6.0 修复: 全部走 hxcore 组件实现(与 50HXUninstaller.exe / GUI 页④ 同源)。
	// 此前内置版只删 Run键+任务+两个旧服务, 且固件启动项用 /enum {fwbootmgr}
	// 定位 — 该段输出没有各启动项 description, "50HX Unlock" 永不匹配 →
	// 启动项删不掉, EFI/GSP/驱动文件也全残留, 卸载后开机仍会执行解锁。
	fmt.Println("=== 卸载 50HX 解锁 (v3.0.0 组件级) ===")
	fmt.Print("[1/8] 删除计划任务 ... ")
	if rem := hxcore.UninstallTasks(); len(rem) > 0 {
		fmt.Println("完成")
	} else {
		fmt.Println("未找到(跳过)")
	}
	fmt.Print("[2/8] 删除 Gen2 Run 键 ... ")
	hxcore.UninstallRunKey()
	fmt.Println("完成")
	fmt.Print("[3/8] 删除固件启动项 '50HX Unlock' ... ")
	if hxcore.UninstallBootEntry() {
		fmt.Println("完成")
	} else {
		fmt.Println("未找到(可能已移除)")
	}
	fmt.Print("[4/8] 删除 ESP 解锁 EFI ... ")
	if hxcore.UninstallEspEfi() {
		fmt.Println("完成")
	} else {
		fmt.Println("未找到/跳过")
	}
	fmt.Println("[5/8] 停止并删除驱动服务...")
	hxcore.UninstallDriverServices()
	fmt.Println("[6/8] 删除驱动文件...")
	hxcore.UninstallDriverFiles()
	fmt.Print("[6.5/8] 删除 EnableGpuFirmware (恢复 GSP 默认关) ... ")
	if hxcore.UninstallGspKey() {
		fmt.Println("完成")
	} else {
		fmt.Println("未找到(跳过)")
	}
	fmt.Print("[6.6/8] 清理 ProgramData + 策略键 ... ")
	hxcore.UninstallProgramData()
	fmt.Println("完成")
	fmt.Print("[6.7/8] 清理 Defender 排除项 ... ")
	if err := hxcore.RemoveDefenderExclusions(); err != nil {
		fmt.Println("未执行(可忽略):", err)
	} else {
		fmt.Println("完成")
	}
	fmt.Println("[7/8] 检查残留...")
	left := hxcore.CheckLeftover()
	fmt.Println()
	fmt.Println("卸载完成。建议重启电脑。")
	fmt.Println("  注: 安装时调整的电源设置(快速启动/ASPM)保留未动 — 恢复方法见 README §2.4。")
	icon := uint(mbIconInfo)
	txt := "卸载完成。\n建议重启电脑。\n\n注: 安装时调整的电源设置(快速启动/ASPM)\n保留未动 — 属电源偏好, 恢复方法见 README §2.4。\n"
	if len(left) > 0 {
		icon = mbIconError
		txt += "\n仍有残留:\n" + strings.Join(left, "\n")
	}
	txt += "\n详细日志: " + filepath.Join(os.TempDir(), "50HX_installer.log")
	msgbox("50HX 安装器", txt, icon)
}

func status() {
	fmt.Println("=== 50HX 解锁状态 ===")
	gpuOK := hxcore.FindGPU()
	sb := hxcore.SecureBootOn()
	ts := hxcore.TestSigningOn()
	gs := hxcore.GspEnabled()
	fmt.Printf("GPU 50HX 检测: %v\n", gpuOK)
	fmt.Printf("Secure Boot: %v\n", sb)
	fmt.Printf("测试签名: %v\n", ts)
	fmt.Printf("GSP 启用 (EnableGpuFirmware=1): %v\n", gs)
	// v2.4.1: GSP 定位诊断 — 伪装/魔改驱动会 AdapterString≠"CMP 50HX"
	if sub, adapter, fw := hxcore.GspDiag(); sub != "" {
		fmt.Printf("  GSP 键: Class\\%s (fw=%d)\n", sub, fw)
		fmt.Printf("  AdapterString: %s\n", adapter)
	} else {
		fmt.Println("  [!] " + adapter) // 无匹配时 hxcore.GspDiag 返回诊断串
	}
	// v2.6.x: Gen2 驱动部署状态(不依赖驱动当前是否运行 — S0 用完即卸后
	// System32 文件缺失属正常终态; 判据是备份源/服务/Defender, 见 hxcore/drvstate.go)
	dep := hxcore.InspectGen2Drivers()
	if !hxcore.Gen2DriversDeployedOnce() {
		fmt.Println("Gen2 驱动: 从未部署 — 运行安装器(页②勾选驱动)后重启生效")
	} else {
		for _, d := range dep {
			svcS := "未注册"
			if d.SvcReg {
				svcS = d.SvcStart
				if d.SvcRunning {
					svcS += "/运行中"
				}
			}
			fmt.Printf("Gen2 驱动 %-16s 备份源=%v  System32=%s  服务=%s\n",
				d.File, map[bool]string{true: "OK", false: "无"}[d.BackupOK], d.SysState.String(), svcS)
		}
	}
	if ex, err := hxcore.DefenderExclusionsPresent(); err != nil {
		fmt.Println("Defender 排除: 查询失败(" + err.Error() + ")")
	} else if ex {
		fmt.Println("Defender 排除: 已加白(OK)")
	} else {
		fmt.Println("Defender 排除: 缺失 — 杀软可能误删驱动, 重跑安装器补加")
	}
	// 驱动与解锁实测: 主判据 = 设备实际可打开(不依赖 sc.exe — 部分安全环境禁用它)
	// v2.5: TS(ThrottleStop) + WinRing0 BYOVD, 不再需要 50hx_bridge
	st := hxcore.ReadUnlockStateV2(5, 800)
	tsRun := st.TSOK
	winringRun := st.WinRingOK
	fmt.Printf("ThrottleStop: %v\n", tsRun)
	fmt.Printf("WinRing0: %v\n", winringRun)
	if tsRun && winringRun {
		fmt.Printf("PCIe 链路: Gen%d\n", st.Speed)
		if st.SS0OK {
			fmt.Printf("SS0(算力): 0x%08x %s\n", st.SS0, map[bool]string{true: "(已解锁)", false: "(锁定)"}[st.Unlocked])
		}
	} else {
		fmt.Println("驱动未运行(装好后 Gen2/状态可用)")
	}
	ss0 := st.SS0
	ss0ok := st.SS0OK
	speed := st.Speed
	// v2.4: 弹窗带诊断与处置建议(社区用户不依赖日志)
	diag := []string{}
	if !gpuOK {
		diag = append(diag, "· 未检测到 50HX —— 请确认显卡已插入且驱动已装")
	}
	if sb {
		diag = append(diag, "· Secure Boot 开启: 需进 BIOS 关闭, 否则解锁 EFI 被拒")
	}
	if ts {
		diag = append(diag, "· 测试签名已开启 — v2.5 不需要, 可 bcdedit /set testsigning off 关闭")
	}
	if !gs {
		diag = append(diag, "· GSP 未启用: 解锁后可能黑屏。运行安装器(自动设 EnableGpuFirmware=1)")
	}
	if !tsRun || !winringRun {
		diag = append(diag, "· 驱动未运行: 重启后登录会自动拉起; 或手动运行 50HXInstaller.exe -gen2")
	}
	if tsRun && winringRun {
		if !ss0ok {
			diag = append(diag, "· 驱动已运行但读不到算力寄存器(异常)")
		} else if ss0 == 0x88888888 {
			diag = append(diag, fmt.Sprintf("· SS0=0x%08x: 算力已解锁! PCIe Gen%d", ss0, speed))
		} else {
			diag = append(diag, fmt.Sprintf("· SS0=0x%08x: 算力仍锁定 —— 重启时 50HX Unlock EFI 未成功执行", ss0))
			// v2.4.4: 读 EFI 解锁日志(50hx_log.txt)做自动诊断, 不再需要人工看日志
			efiDiag := hxcore.AnalyzeEfiLog()
			if efiDiag != "" {
				diag = append(diag, efiDiag)
			}
		}
	}
	msg := "50HX 解锁状态\n========================\n"
	msg += fmt.Sprintf("GPU 40HX: %v    Secure Boot: %v\n", map[bool]string{true: "✓", false: "✗"}[gpuOK], map[bool]string{true: "开启!", false: "关闭(OK)"}[sb])
	msg += fmt.Sprintf("测试签名: %v    GSP: %v\n", map[bool]string{true: "✓", false: "✗"}[ts], map[bool]string{true: "✓", false: "✗"}[gs])
	msg += fmt.Sprintf("ThrottleStop: %v  WinRing0: %v\n", map[bool]string{true: "✓", false: "✗"}[tsRun], map[bool]string{true: "✓", false: "✗"}[winringRun])
	if tsRun && winringRun {
		msg += fmt.Sprintf("PCIe: Gen%d    SS0: 0x%08x\n", speed, ss0)
	}
	msg += "\n诊断:\n" + strings.Join(diag, "\n")
	if len(diag) == 0 {
		msg += "· 一切正常"
	}
	msg += "\n\n详细日志: " + filepath.Join(os.TempDir(), "50HX_installer.log")
	msgbox("50HX 状态", msg, mbIconInfo)
	fmt.Println("=== 状态结束 ===")
}

func pause() {
	// GUI 版: 无需按 Enter; 输出已入日志, 交互收尾用消息框
}
