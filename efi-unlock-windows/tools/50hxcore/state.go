package hxcore

import (
	"fmt"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

// SS0 compute-unlock register offset (BAR0).
const SS0Offset = 0x409664

// SS1 offset (secondary flag) — v3.0 fix: 0x409668 is the SS0 read-only
// mirror (SS0_READOUT); the real SS1 override lives at 0x40966C (matching
// the EFI REG_FEAT_OVR_SM_SPD_1 write entry). This only affects the
// SS1 value displayed by 40HXCheck / diagnostics — the unlock decision
// uses SS0 alone.
const SS1Offset = 0x40966C

// UnlockState is a one-shot snapshot of "did the unlock succeed".
type UnlockState struct {
	BridgeOK  bool   // \\.\50hxBridge openable
	WinRingOK bool   // \\.\WinRing0_1_2_0 openable
	TSOK      bool   // \\.\ThrottleStop openable (v2.5 BYOVD channel)
	Speed     uint32 // PCIe gen (0=unknown)
	Width     uint32 // Negotiated link width in lanes (0=unknown; x1/x2/x4/x8/x16/x32)
	TLS       uint32 // GPU LNKCTL2 target link speed (0=unknown); v2.5.1: Speed<2 yet TLS>=2
	//               // = idle power-saving downshift (configured; auto-restores under load), not an unlock failure
	SS0      uint32 // Compute-capability flag register
	SS1      uint32
	SS0OK    bool // Successfully read SS0
	Unlocked bool // SS0 == 0x88888888
}

// The 50HX's LocationInformation in the PCI enum is shaped like
// "PCI bus 1, device 0, function 0" (on Chinese systems:
// "PCI 总线 1, 设备 0, 功能 0"). Cross-locale compatibility: extract only
// the bus/dev/fn numbers.
var locNumRe = regexp.MustCompile(`\d+`)

// FindGPUBDFFromRegistry parses the BDF out of the LocationInformation of
// an Enum\PCI\VEN_10DE&DEV_1E09 instance. Used for devices that PCI config
// scanning cannot reach (cheap boards / multi-level bridges / 50HX sitting
// at bus>=8 — issue #9, MSI B450+5600G is a known example).
// Returns 0, false when not found.
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

// FindGPUPCI does a full PCI-config scan to locate the 50HX's BDF
// (bus<<8|dev<<3|fn). Matches only VEN_10DE + DEV_1E09 — won't
// mis-identify a device in multi-GPU / non-bus-1 topologies.
//
// v2.5.1 fix (issue #9, MSI B450+5600G: "boot/diagnostics can't find
// 40HX"): the original implementation only scanned bus 0-7. On B450+APU,
// cheap boards, multi-level bridges etc. the 50HX is often enumerated at
// bus>=8 (or higher), so the scan always missed it → gen2Main simply
// reported "unable to locate 40HX on the PCI bus" and gave up. Now a
// three-stage locator:
//   1) Fast path: bus 0-7 (covers the vast majority of single-GPU hosts)
//   2) Fallback #1: take the known BDF from the registry's
//      LocationInformation and verify it (fastest and most reliable;
//      doesn't depend on whether WinRing0 can scan PCI config)
//   3) Fallback #2: scan bus 8-255 (multi-level bridges / high-bus
//      topologies)
func FindGPUPCI(wh syscall.Handle) (uint32, bool) {
	// 1) Fast path: bus 0-7.
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
	// 2) Fallback #1: registry-known location (cross-bus topology),
	// directly verify the BDF.
	if bdf, ok := FindGPUBDFFromRegistry(); ok {
		if id, err := PciRd(wh, bdf, 0x00); err == nil && id != 0xFFFFFFFF &&
			id&0xFFFF == 0x10DE && (id>>16)&0xFFFF == 0x1E09 {
			return bdf, true
		}
	}
	// 3) Fallback #2: scan the higher buses 8-255.
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

// ReadUnlockState opens the two drivers and reads SS0/SS1/link speed.
// retries: how many times to retry when the driver is not yet ready
// (just got to the desktop, driver still loading);
// delayMs: delay between retries. Suitable for waiting on driver readiness
// immediately after logon.
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

	// PCIe gen: first locate the 50HX's BDF by VEN/DEV, then read its
	// link speed (skipping device-identity check would misread the speed
	// of other PCIe devices — the multi-GPU / non-bus-1 trap).
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

// ReadUnlockStateV2 is the v2.5 channel — WinRing0 (config: link /
// locating the card / BAR0 base) + ThrottleStop (BYOVD, reading SS0/SS1).
// Works in normal mode, with no 50hx_bridge and no test signature.
func ReadUnlockStateV2(retries int, delayMs int) *UnlockState {
	st := &UnlockState{}
	wh, err2 := OpenDevice(`\\.\WinRing0_1_2_0`)
	for i := 0; err2 != nil && i < retries; i++ {
		wh, err2 = OpenDevice(`\\.\WinRing0_1_2_0`)
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}
	if err2 != nil {
		return st // No WinRing0 → cannot read config / BAR0 base.
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

	// v2.5: ThrottleStop BYOVD channel.
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

// ScServiceRunning queries whether the service is RUNNING (sc.exe query).
// Returns false on query failure or when not running.
func ScServiceRunning(name string) bool {
	out, err := RunOut("sc.exe", "query", name)
	if err != nil {
		return false
	}
	return strings.Contains(out, "RUNNING") || strings.Contains(strings.ToLower(out), "running")
}
