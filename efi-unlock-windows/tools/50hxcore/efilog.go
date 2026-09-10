package hxcore

import (
	"os"
	"strings"
)

// AnalyzeEfiLog: 读 ESP 根目录 50hx_log.txt (EFI 解锁链日志), 按失败特征
// 分类给出精确解决步骤。SS0 锁定时调用; 返回诊断建议字符串(可多行)。
//
// v2.4.4: 社区 #1 (X99 双卡 code43) 教训 — 相同症状可能来自不同根因:
//   A. "WPR2 NOT up" + "IMEM[0]=0xffffffff"  → GPU DMA 够不到 >4GB 载荷
//      = 主板 Above 4G Decoding 未开 (开发机 Z170 开了才成功)
//   B. "not-OK (m0=0x89 halted)" → booter 注入失败 (时序/槽位问题)
//   C. 日志显示已 UNLOCKED 但 SS0 锁 → 驱动层覆盖(重跑安装器)
//   D. 无日志 → EFI 没跑 (启动项未置顶/Secure Boot)
func AnalyzeEfiLog() string {
	esp := MountESP()
	if esp == "" {
		return "  [EFI日志] 无法挂载 ESP(需管理员) — 无法读取解锁日志"
	}
	defer UnmountESP(esp)
	// v3.0.0: 先确认解锁 EFI 本体是否还在 —— 卸载 EFI 后 ESP 根目录的
	// 50hx_log.txt 是历史残留, 不能再拿去套"booter 失败/换槽/Above4G"这类
	// 分析(会给没装 EFI 的用户派无关引导, 社区实机踩过)。
	efiPath := esp + `:\EFI\50HX\50HXUNLK.EFI`
	_, efiErr := os.Stat(efiPath)
	p := esp + ":\\50hx_log.txt"
	data, err := os.ReadFile(p)
	if err != nil {
		if efiErr != nil {
			return "  [EFI日志] 解锁 EFI 未部署/已卸载(ESP 上无 \\EFI\\50HX\\50HXUNLK.EFI, 也无 50hx_log.txt)\n  算力保持锁定属预期; 想解锁算力: 50HXInstaller.exe 勾选[算力 EFI 部署+固件启动项]安装"
		}
		return "  [EFI日志] ESP 上无 50hx_log.txt — EFI 可能没执行\n  请进 BIOS: 将 '50HX Unlock' 置为第一启动项 或 关 Secure Boot"
	}
	if efiErr != nil {
		return "  [EFI日志] 注: ESP 根目录的 50hx_log.txt 是历史残留 — 解锁 EFI 已不在(已卸载/未安装)\n  旧日志不代表当前状态; 算力锁定属预期, 想恢复请重装[算力 EFI 部署+固件启动项]"
	}
	low := strings.ToLower(string(data))
	hit := func(s string) bool { return strings.Contains(low, strings.ToLower(s)) }

	// 解锁成功标志优先 (注意: "SEC2 unlocked" 仅指核可注入, 非算力解锁!
	// 必须匹配算力解锁特征 "*** UNLOCKED ***" 或 SS0 实际值)
	if hit("*** unlocked ***") || hit("already unlocked (ss0/ss1 exact)") {
		return "  [EFI日志] 解锁链实际已 UNLOCKED — 是驱动层覆盖了状态\n  请重跑一次安装器(重设 GSP)后重启, 或换回作者实测驱动版本"
	}
	// 失败模式 A: DMA 够不到 >4GB (Above 4G 未开)
	if hit("wpr2 not up") || (hit("imem[0]=0xffffffff") && hit("fwsec40")) {
		r := "  [EFI日志] WPR2 拉不起 + DMA 读返回全F\n"
		r += "  → GPU 访问不到 >4GB 解锁载荷。这是 BIOS 设置问题, 请逐项检查:\n"
		r += "  1. Above 4G Decoding / 4G以上解码 → Enabled ← 最常见!\n"
		r += "  2. Resizable BAR / 大BAR → Auto/Enabled (若选项存在)\n"
		r += "  3. 50HX 换到第一个 PCIe x16 槽(CPU直连)\n"
		r += "  4. Fast Boot → Disabled\n"
		r += "  (X99: Advanced/PCI Subsystem 里找 Above 4G)"
		return r
	}
	// 失败模式 B: booter HALT 且最终未解锁 (成功日志也有 attempt not-OK 但会续试成功)
	if hit("final]: plm=") && hit("ss0=0x00000000") && (hit("halted") || hit("not-ok")) {
		r := "  [EFI日志] booter 注入失败(多次 HALT, 最终 SS0 仍为 0)\n"
		r += "  → 双卡/非第一槽时序问题, 请逐项检查:\n"
		r += "  1. 50HX 换到第一个 PCIe x16 槽(避开 PLX/桥接)\n"
		r += "  2. Above 4G Decoding → Enabled\n"
		r += "  3. Fast Boot → Disabled\n"
		r += "  4. 若为多卡: 暂时拔掉其它卡只留 50HX 测一次"
		return r
	}
	// 失败模式 C (v3.0): EFI 找不到卡 — 旧版只扫 bus 0-7/0-16, AGESA/桥接
	// 板把独显编到高总线 (微星 B450 实测 bus 0x10=16) 时必然 miss。
	if hit("gpu not found; abort") || hit("not found (both encodings)") {
		r := "  [EFI日志] EFI 找不到卡: 多为 PCI 总线编号超出旧版扫描范围\n"
		r += "  (AGESA/微星 B450 等板型把独显编到 bus≥16, 或走 PLX/多级桥接)\n"
		r += "  → 请用 v3.0 安装器重装解锁 EFI (已支持 CF8 全 256 总线扫描) 后\n"
		r += "    完全关机再开机一次; 仍失败请把本日志全文贴回 issue"
		return r
	}
	// 未知失败: 摘录关键行给用户贴
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
	return "  [EFI日志] 未能自动归类, 关键行:\n  " + strings.Join(key, "\n  ")
}
