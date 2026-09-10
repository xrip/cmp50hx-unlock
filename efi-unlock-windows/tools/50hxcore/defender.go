package hxcore

// Defender 驱动排除与实时防护管理。
//
// 背景: WinRing0x64.sys / ThrottleStop.sys 这类底层驱动可能被安全软件当作
// HackTool/漏洞驱动隔离(常见表现: 文件变 0 字节占位) → Gen2 自启失败。
// 本模块提供:
//   1. 加白(默认, 精确到本项目文件, 不关闭任何系统防护; 卸载时同名移除)
//   2. 可选关闭实时防护(高风险, 仅当驱动反复被隔离时用, 默认不勾)
//   3. 状态查询(排除列表 / 实时防护是否开启) — 供扫描与界面提示
//
// 编码: PowerShell 输出经管道回读是系统 ANSI(GBK), 直接按 UTF-8 解读会乱码
// (曾把报错显示成一串乱码)。统一在命令前设 [Console]::OutputEncoding=UTF8。
//
// 兼容: 第三方杀软接管或精简系统会把 Defender 管理模块整个拿掉,
// 此时 Add/Remove/Get-MpPreference 报"不是 cmdlet" — mpErr 识别后给中文提示。

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// psUtf8: 让 powershell 以 UTF-8 向管道输出(避免中文报错在日志里乱码)
const psUtf8 = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"

// Gen2DrvFiles: v2.5 BYOVD 用到的两个驱动文件名。
func Gen2DrvFiles() []string {
	return []string{"ThrottleStop.sys", "WinRing0x64.sys"}
}

// ExclusionPaths: 需要加白的具体路径(精确到文件/目录)。
//   1-2. System32\drivers 下的两个驱动文件
//   3.   %ProgramData%\50HXUnlock\drivers 备份源
//   4.   当前 exe 所在目录(随入口变化, 不作查询判定项)
func ExclusionPaths() []string {
	var ps []string
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	for _, f := range Gen2DrvFiles() {
		ps = append(ps, filepath.Join(sys, "System32", "drivers", f))
	}
	ps = append(ps, PdDrvDir())
	if exe, err := os.Executable(); err == nil {
		ps = append(ps, filepath.Dir(exe))
	}
	return ps
}

// psArray: 拼 PowerShell 数组字面量 @('a','b'), 单引号包裹路径。
func psArray(ps []string) string {
	q := make([]string, 0, len(ps))
	for _, p := range ps {
		q = append(q, "'"+strings.ReplaceAll(p, "'", "''")+"'")
	}
	return "@(" + strings.Join(q, ",") + ")"
}

// ErrMpUnavailable: Defender 管理模块缺失(第三方杀软接管/精简系统把模块拿掉)。
// 供调用方 errors.Is 判断后显示简短提示, 避免把整段报错嵌套进界面文案。
var ErrMpUnavailable = errors.New("Defender 管理模块不可用")

// mpErr: 把 Defender 相关命令的错误转成人话 — 最常见的根因是模块不存在
// (第三方杀软接管/精简系统把 Defender 模块拿掉), 给出明确后续动作。
func mpErr(action, out string, err error) error {
	low := strings.ToLower(out)
	switch {
	case strings.Contains(low, "not recognized"),
		strings.Contains(low, "commandnotfoundexception"),
		strings.Contains(out, "不是内部"),
		strings.Contains(out, "无法将"):
		return fmt.Errorf("%w: 本机未安装 Defender 管理模块(%s)", ErrMpUnavailable, action)
	}
	msg := strings.TrimSpace(out)
	if len(msg) > 200 {
		msg = msg[:200]
	}
	if msg != "" {
		return fmt.Errorf("%s 失败: %v %s", action, err, msg)
	}
	return fmt.Errorf("%s 失败: %v", action, err)
}

func runMp(cmd string) (string, error) {
	return RunOut("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", psUtf8+cmd)
}

// AddDefenderExclusions: 安装时调用 — 把驱动文件/备份目录加进 Defender 排除。
// 失败返回错误(模块缺失会有对应提示); 驱动能正常加载时不影响, 仅防误删增强。
func AddDefenderExclusions() error {
	ps := ExclusionPaths()
	if len(ps) == 0 {
		return fmt.Errorf("无排除路径")
	}
	out, err := runMp("Add-MpPreference -ExclusionPath " + psArray(ps))
	if err != nil {
		return mpErr("添加 Defender 排除", out, err)
	}
	return nil
}

// RemoveDefenderExclusions: 卸载时调用 — 清理本工具加过的排除项(精确同名移除)。
func RemoveDefenderExclusions() error {
	ps := ExclusionPaths()
	if len(ps) == 0 {
		return nil
	}
	out, err := runMp("Remove-MpPreference -ExclusionPath " + psArray(ps))
	if err != nil {
		return mpErr("移除 Defender 排除", out, err)
	}
	return nil
}

// DefenderExclusionsPresent: 查询排除列表是否已含固定项(两个 System32 .sys + 备份目录)。
// 返回 (是否全部命中, 错误)。查询失败(模块缺失等)返回错误, 调用方提示"无法查询"。
func DefenderExclusionsPresent() (bool, error) {
	out, err := runMp("@((Get-MpPreference).ExclusionPath) | ConvertTo-Json -Compress")
	if err != nil {
		return false, mpErr("查询 Defender 排除", out, err)
	}
	out = strings.TrimSpace(out)
	if out == "" || out == "null" {
		return false, nil
	}
	var paths []string
	if strings.HasPrefix(out, "[") {
		if err := json.Unmarshal([]byte(out), &paths); err != nil {
			return false, fmt.Errorf("解析 Defender 排除列表失败: %v", err)
		}
	} else {
		// PowerShell ConvertTo-Json 对单元素数组会拍平成标量
		var s string
		if err := json.Unmarshal([]byte(out), &s); err != nil {
			return false, fmt.Errorf("解析 Defender 排除列表失败: %v", err)
		}
		paths = []string{s}
	}
	var want []string
	sys := os.Getenv("SystemRoot")
	if sys == "" {
		sys = `C:\Windows`
	}
	for _, f := range Gen2DrvFiles() {
		want = append(want, filepath.Join(sys, "System32", "drivers", f))
	}
	want = append(want, PdDrvDir())
	trim := func(p string) string { return strings.TrimRight(strings.TrimSpace(p), `\`) }
	hit := 0
	for _, w := range want {
		for _, p := range paths {
			if strings.EqualFold(trim(p), trim(w)) {
				hit++
				break
			}
		}
	}
	return hit == len(want), nil
}

// DefenderRealtimeProtectionOn: 查询 Defender 实时防护当前是否开启。
func DefenderRealtimeProtectionOn() (bool, error) {
	out, err := runMp("(Get-MpComputerStatus).RealTimeProtectionEnabled | ConvertTo-Json -Compress")
	if err != nil {
		return false, mpErr("查询 Defender 实时防护", out, err)
	}
	switch strings.ToLower(strings.TrimSpace(out)) {
	case "true", "1":
		return true, nil
	case "false", "0", "":
		return false, nil
	}
	return false, fmt.Errorf("查询 Defender 实时防护返回异常: %s", strings.TrimSpace(out))
}

// SetDefenderRealtimeProtection: 关闭(on=false)或恢复开启(on=true) Defender 实时防护。
// 高风险操作 — 调用方(GUI)需以显式勾选 + 明确提示为前提。
func SetDefenderRealtimeProtection(on bool) error {
	v := "False"
	act := "关闭"
	if on {
		v = "True"
		act = "恢复开启"
	}
	out, err := runMp("Set-MpPreference -DisableRealtimeMonitoring $" + v)
	if err != nil {
		return mpErr(act+" Defender 实时防护(若 Windows 安全中心开了'篡改防护'会被拒绝, 请先关闭它)", out, err)
	}
	return nil
}
