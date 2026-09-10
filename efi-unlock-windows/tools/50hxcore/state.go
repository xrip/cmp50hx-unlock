package hxcore

import (
	"fmt"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

// SS0 算力解锁寄存器偏移 (BAR0)
const SS0Offset = 0x409664

// SS1 偏移 (副标志) — v3.0 修正: 0x409668 是 SS0 只读回读镜像 (SS0_READOUT),
// 真正的 SS1 override 在 0x40966C (与 EFI REG_FEAT_OVR_SM_SPD_1 写入口一致)。
// 只影响 40HXCheck/诊断的 SS1 显示值, 不影响解锁判定 (判定只看 SS0)。
const SS1Offset = 0x40966C

// UnlockState: 一次"解锁是否成功"实测快照
type UnlockState struct {
	BridgeOK  bool   // \\.\50hxBridge 可打开
	WinRingOK bool   // \\.\WinRing0_1_2_0 可打开
	TSOK      bool   // \\.\ThrottleStop 可打开 (v2.5 BYOVD 通道)
	Speed     uint32 // PCIe gen (0=未知)
	Width     uint32 // 协商链路宽度 lanes (0=未知; ×1/×2/×4/×8/×16/×32)
	TLS       uint32 // GPU LNKCTL2 目标速率 (0=未知); v2.5.1: Speed<2 而 TLS>=2
	//               // = 空闲省电降速(已配置, 负载自动回升), 不是解锁失败
	SS0      uint32 // 算力标志寄存器
	SS1      uint32
	SS0OK    bool // 成功读到 SS0
	Unlocked bool // SS0 == 0x88888888
}

// 50HX 在 PCI 枚举里的 LocationInformation 形如 "PCI bus 1, device 0, function 0"
// (中文系统为 "PCI 总线 1, 设备 0, 功能 0")。跨语言兼容: 只抽数字 bus/dev/fn。
var locNumRe = regexp.MustCompile(`\d+`)

// FindGPUBDFFromRegistry: 从 Enum\PCI\VEN_10DE&DEV_1E09 实例的
// LocationInformation 解析 BDF。用于 PCI config 扫描够不到的设备(寨板/多级桥接/
// 50HX 位于 bus>=8 等拓扑, issue #9 微星 B450+5600G 即此类)。
// 找不到返回 0,false。
func FindGPUBDFFromRegistry() (uint32, bool) {
	base, err := registry.OpenKey(registry.LOCAL_MACHINE, GpuEnumBase, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return 0, false
	}
	defer base.Close()
	devs, err := base.ReadSubKeyNames(-1)
	if err != nil {
		return 0, false
	}
	for _, d := range devs {
		if !strings.Contains(d, GpuVenDev) {
			continue
		}
		dk, err := registry.OpenKey(registry.LOCAL_MACHINE, GpuEnumBase+`\`+d, registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		insts, _ := dk.ReadSubKeyNames(-1)
		dk.Close()
		for _, inst := range insts {
			ik, err := registry.OpenKey(registry.LOCAL_MACHINE, GpuEnumBase+`\`+d+`\`+inst, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			loc, _, e := ik.GetStringValue("LocationInformation")
			ik.Close()
			if e != nil {
				continue
			}
			nums := locNumRe.FindAllString(loc, -1)
			if len(nums) >= 3 {
				var n [3]uint32
				for i := 0; i < 3; i++ {
					fmt.Sscanf(nums[i], "%d", &n[i])
				}
				return (n[0] << 8) | (n[1] << 3) | n[2], true
			}
		}
	}
	return 0, false
}

// FindGPUPCI: 全扫 PCI config 定位 50HX 的 BDF (bus<<8|dev<<3|fn)。
// 只认 VEN_10DE + DEV_1E09 — 多卡/非 bus1 拓扑也不会认错设备。
//
// v2.5.1 修复(issue #9 微星 B450+5600G「引导/诊断都找不到 40HX」):
// 原实现只扫 bus 0-7。在 B450+APU/寨板/多级桥接等拓扑下, 50HX 常被枚举到
// bus>=8(甚至更高), 导致扫描永远漏掉它 → gen2Main 直接报"未能在 PCI 总线上
// 定位 40HX"而放弃。现改为三层定位:
//   1) 快速路径: bus 0-7 (覆盖绝大多数单卡)
//   2) 兜底1: 从注册表 LocationInformation 取已知 BDF 并验证(最快最稳,
//      不依赖 PCI config 能否被 WinRing0 扫到)
//   3) 兜底2: 补扫 bus 8-255 (多级桥接/高总线拓扑)
func FindGPUPCI(wh syscall.Handle) (uint32, bool) {
	// 1) 快速路径 bus 0-7
	for bus := uint32(0); bus < 8; bus++ {
		for dev := uint32(0); dev < 32; dev++ {
			for fn := uint32(0); fn < 8; fn++ {
				bdf := (bus << 8) | (dev << 3) | fn
				id, err := PciRd(wh, bdf, 0x00)
				if err != nil || id == 0xFFFFFFFF {
					continue
				}
				if id&0xFFFF == 0x10DE && (id>>16)&0xFFFF == 0x1E09 {
					return bdf, true
				}
			}
		}
	}
	// 2) 兜底1: 注册表已知位置(跨总线拓扑), 直接验证该 BDF
	if bdf, ok := FindGPUBDFFromRegistry(); ok {
		if id, err := PciRd(wh, bdf, 0x00); err == nil && id != 0xFFFFFFFF &&
			id&0xFFFF == 0x10DE && (id>>16)&0xFFFF == 0x1E09 {
			return bdf, true
		}
	}
	// 3) 兜底2: 补扫更高总线 8-255
	for bus := uint32(8); bus < 256; bus++ {
		for dev := uint32(0); dev < 32; dev++ {
			for fn := uint32(0); fn < 8; fn++ {
				bdf := (bus << 8) | (dev << 3) | fn
				id, err := PciRd(wh, bdf, 0x00)
				if err != nil || id == 0xFFFFFFFF {
					continue
				}
				if id&0xFFFF == 0x10DE && (id>>16)&0xFFFF == 0x1E09 {
					return bdf, true
				}
			}
		}
	}
	return 0, false
}

// ReadUnlockState: 打开两驱动并读 SS0/SS1/链路速率。
// retries: 驱动未就绪(刚进桌面驱动还在加载)时的重试次数;
// delayMs: 每次重试间隔。适合登录后立刻调用时等待驱动就绪。
func ReadUnlockState(retries int, delayMs int) *UnlockState {
	st := &UnlockState{}
	bh, err1 := OpenDevice(`\\.\50hxBridge`)
	wh, err2 := OpenDevice(`\\.\WinRing0_1_2_0`)
	for i := 0; (err1 != nil || err2 != nil) && i < retries; i++ {
		if err1 != nil {
			bh, err1 = OpenDevice(`\\.\50hxBridge`)
		}
		if err2 != nil {
			wh, err2 = OpenDevice(`\\.\WinRing0_1_2_0`)
		}
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}
	if err1 != nil || err2 != nil {
		if err1 != nil {
			CloseHandle(bh)
		}
		if err2 != nil {
			CloseHandle(wh)
		}
		return st
	}
	defer CloseHandle(bh)
	defer CloseHandle(wh)
	st.BridgeOK, st.WinRingOK = true, true

	// PCIe gen: 先按 VEN/DEV 定位 50HX 的 BDF, 再读它的 link speed
	// (不校验设备身份会误读其它 PCIe 设备的速率 — 多卡/非 bus1 拓扑的坑)
	if bdf, ok := FindGPUPCI(wh); ok {
		st.Speed = LinkSpeed(wh, bdf)
	}
	if v, err := Bar0Rd(bh, SS0Offset); err == nil {
		st.SS0, st.SS0OK = v, true
		st.Unlocked = v == 0x88888888
	}
	if v, err := Bar0Rd(bh, SS1Offset); err == nil {
		st.SS1 = v
	}
	return st
}

// ReadUnlockStateV2: v2.5 通道 — WinRing0(config: 链路/找卡/BAR0 基址) +
// ThrottleStop(BYOVD, 读 SS0/SS1)。普通模式、无 50hx_bridge、无测试签名也能判定。
func ReadUnlockStateV2(retries int, delayMs int) *UnlockState {
	st := &UnlockState{}
	wh, err2 := OpenDevice(`\\.\WinRing0_1_2_0`)
	for i := 0; err2 != nil && i < retries; i++ {
		wh, err2 = OpenDevice(`\\.\WinRing0_1_2_0`)
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}
	if err2 != nil {
		return st // 无 WinRing0 就无法读 config / BAR0 基址
	}
	defer CloseHandle(wh)
	st.WinRingOK = true

	bdf, ok := FindGPUPCI(wh)
	if !ok {
		return st
	}
	st.Speed = LinkSpeed(wh, bdf)
	st.Width = LinkWidth(wh, bdf)
	if cap := PcieCap(wh, bdf); cap != 0 {
		if v, err := PciRd(wh, bdf, cap+0x30); err == nil {
			st.TLS = v & 0xF
		}
	}
	bar0raw, err := PciRd(wh, bdf, 0x10)
	if err != nil {
		return st
	}
	bar0 := uint64(bar0raw & 0xFFFFFFF0)

	// v2.5: ThrottleStop BYOVD 通道
	th, err3 := OpenThrottleStop()
	for i := 0; err3 != nil && i < retries; i++ {
		th, err3 = OpenThrottleStop()
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}
	if err3 != nil {
		return st
	}
	defer CloseHandle(th)
	st.TSOK = true
	if v, err := TSRead(th, bar0+SS0Offset); err == nil {
		st.SS0, st.SS0OK, st.Unlocked = v, true, v == 0x88888888
	}
	if v, err := TSRead(th, bar0+SS1Offset); err == nil {
		st.SS1 = v
	}
	return st
}

// ScServiceRunning: 查询服务是否 RUNNING (sc.exe query)
// 返回 false 表示查询失败或未运行。
func ScServiceRunning(name string) bool {
	out, err := RunOut("sc.exe", "query", name)
	if err != nil {
		return false
	}
	return strings.Contains(out, "RUNNING") || strings.Contains(strings.ToLower(out), "running")
}
