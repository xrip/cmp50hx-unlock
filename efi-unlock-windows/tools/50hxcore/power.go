package hxcore

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// v2.5.1: 两个影响"解锁开机链路稳定性"的系统电源设置。
// 来源: 社区 v2.4.5 时代排障结论 + v2.5 时期 #1/#3 反馈 —
//  1. 快速启动(混合休眠): "关机→再开机"走休眠恢复, 不做完整 UEFI 引导,
//     解锁 EFI 可能不执行 → "装完没反应/算力仍锁"。
//  2. PCIe 链路状态电源管理(ASPM): 开启时 GPU 空闲会被驱动降到 Gen1 省电,
//     登录后实测读数容易误报"Gen2 失败"(实际负载下自动回 Gen2)。
// 两项均只影响电源行为, 不碰系统防护; 都可在原设置界面/命令恢复。

// FastStartupOn: Windows 快速启动(混合休眠)是否开启 (HiberbootEnabled=1)。
// 键不存在(老系统/休眠未启用)视为关。
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

// SetFastStartupOff: 关闭快速启动(仅混合休眠, 休眠功能本身保留)。
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

// ASPMSavings: 当前电源计划的 PCIe 链路状态电源管理(ASPM)设置。
// 返回 (交流, 直流, 是否可检测)。0=关闭 1=中等省电 2=最大省电。
func ASPMSavings() (uint32, uint32, bool) {
	out, err := RunOut("powercfg", "-q", "SCHEME_CURRENT", "SUB_PCIEXPRESS", "ASPM")
	if err != nil || !strings.Contains(out, "ee12f906") {
		return 0, 0, false
	}
	// 输出末两处 0x???????? 依次为 AC/DC 当前索引
	// ("可能的设置索引"行无 0x 前缀, 不会混入; 中英文输出格式一致)
	m := rePowerIdx.FindAllStringSubmatch(out, -1)
	if len(m) < 2 {
		return 0, 0, false
	}
	ac, _ := strconv.ParseUint(m[len(m)-2][1], 16, 32)
	dc, _ := strconv.ParseUint(m[len(m)-1][1], 16, 32)
	return uint32(ac), uint32(dc), true
}

// SetASPMOff: 把当前电源计划的 PCIe 链路状态电源管理设为关闭(AC+DC 并立即生效)。
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

// 高性能电源计划 GUID (Windows 内置, 所有语言一致)
const highPerfPlanGUID = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"

// HighPerfPlanActive: 当前电源计划是否已是"高性能"。
func HighPerfPlanActive() bool {
	out, err := RunOut("powercfg", "/getactivescheme")
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(out), highPerfPlanGUID)
}

// SetHighPerfPlan: 切换到高性能电源计划(可随时在电源选项改回, 非破坏性)。
func SetHighPerfPlan() error {
	out, err := RunOut("powercfg", "/setactive", highPerfPlanGUID)
	if err != nil {
		return fmt.Errorf("切换高性能电源计划失败: %s", strings.TrimSpace(out))
	}
	return nil
}
