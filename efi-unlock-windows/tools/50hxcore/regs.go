package hxcore

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

// ---- Low-level handle / ioctl (50hx_bridge + WinRing0) ----
var (
	k32 = syscall.NewLazyDLL("kernel32.dll")
	// Lazy-init for gen2 / diagnostics.
	createFileW = k32.NewProc("CreateFileW")
	devIoCtrl   = k32.NewProc("DeviceIoControl")
	closeHandle = k32.NewProc("CloseHandle")
)

const (
	// 50hx_bridge
	ioctlRb = (40001 << 16) | (0x800 << 2)
	ioctlWb = (40001 << 16) | (0x801 << 2)
	// WinRing0 (CTL(fn,acc) = (40000<<16)|(acc<<14)|(fn<<2))
	ioctlRpci = (40000 << 16) | (1 << 14) | (0x851 << 2)
	ioctlWpci = (40000 << 16) | (2 << 14) | (0x852 << 2)
)

type bar0RdIn struct {
	Offset uint64
	Count  uint32
}
type bar0WrIn struct {
	Offset uint64
	Value  uint32
}
type bar0WrOut struct {
	Old uint32
	New uint32
}
type pciIoIn struct {
	BDF uint32
	Reg uint32
}

// OpenDevice opens a device such as \\.\50hxBridge or \\.\WinRing0_1_2_0.
func OpenDevice(name string) (syscall.Handle, error) {
	ptr, _, _ := createFileW.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
		0xC0000000, // GENERIC_READ|GENERIC_WRITE
		0, 0,       // shareMode=0, securityAttributes=NULL
		3,          // OPEN_EXISTING
		0x80, 0)    // FILE_ATTRIBUTE_NORMAL, no template
	if ptr == uintptr(syscall.InvalidHandle) {
		return 0, errors.New("open " + name + " failed")
	}
	return syscall.Handle(ptr), nil
}

// IoCtl is a DeviceIoControl wrapper.
func IoCtl(h syscall.Handle, code uint32, in []byte, out []byte) (uint32, error) {
	var n uint32
	var inPtr, outPtr uintptr
	var inLen, outLen uint32
	if len(in) > 0 {
		inPtr = uintptr(unsafe.Pointer(&in[0]))
		inLen = uint32(len(in))
	}
	if len(out) > 0 {
		outPtr = uintptr(unsafe.Pointer(&out[0]))
		outLen = uint32(len(out))
	}
	r, _, e := devIoCtrl.Call(uintptr(h), uintptr(code), inPtr, uintptr(inLen),
		outPtr, uintptr(outLen), uintptr(unsafe.Pointer(&n)), 0)
	if r == 0 {
		return 0, errors.New(fmt.Sprintf("ioctl 0x%x err=%v", code, e))
	}
	return n, nil
}

// CloseHandle closes a device handle.
func CloseHandle(h syscall.Handle) {
	if h != 0 {
		closeHandle.Call(uintptr(h))
	}
}

// ---- BAR0 via 50hx_bridge ----

// Bar0Rd reads 4 bytes from GPU BAR0 at the given offset.
func Bar0Rd(bh syscall.Handle, off uint64) (uint32, error) {
	in := bar0RdIn{Offset: off, Count: 1}
	out := make([]byte, 4)
	ib := make([]byte, 12)
	binary.LittleEndian.PutUint64(ib[0:], in.Offset)
	binary.LittleEndian.PutUint32(ib[8:], in.Count)
	_, err := IoCtl(bh, ioctlRb, ib, out)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(out), nil
}

// Bar0Wr writes to GPU BAR0 (returns old/new value).
func Bar0Wr(bh syscall.Handle, off uint64, val uint32) (uint32, uint32, error) {
	ib := make([]byte, 12)
	binary.LittleEndian.PutUint64(ib[0:], off)
	binary.LittleEndian.PutUint32(ib[8:], val)
	ob := make([]byte, 8)
	_, err := IoCtl(bh, ioctlWb, ib, ob)
	if err != nil {
		return 0, 0, err
	}
	return binary.LittleEndian.Uint32(ob[0:]), binary.LittleEndian.Uint32(ob[4:]), nil
}

// ---- PCI config via WinRing0 ----

// PciRd reads PCI config (bdf=bus<<8|dev<<3|fn).
func PciRd(wh syscall.Handle, bdf uint32, reg uint32) (uint32, error) {
	ib := make([]byte, 8)
	binary.LittleEndian.PutUint32(ib[0:], bdf)
	binary.LittleEndian.PutUint32(ib[4:], reg)
	ob := make([]byte, 4)
	_, err := IoCtl(wh, ioctlRpci, ib, ob)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(ob), nil
}

// PciWr writes PCI config.
func PciWr(wh syscall.Handle, bdf uint32, reg uint32, data []byte) error {
	ib := make([]byte, 8+len(data))
	binary.LittleEndian.PutUint32(ib[0:], bdf)
	binary.LittleEndian.PutUint32(ib[4:], reg)
	copy(ib[8:], data)
	_, err := IoCtl(wh, ioctlWpci, ib, nil)
	return err
}

// PcieCap locates the PCIe capability pointer; 0=not found.
func PcieCap(wh syscall.Handle, bdf uint32) uint32 {
	hdr, err := PciRd(wh, bdf, 0x34)
	if err != nil {
		return 0
	}
	cur := hdr & 0xFF
	for i := 0; i < 20; i++ {
		if cur < 0x40 || cur > 0xFF {
			return 0
		}
		c, err := PciRd(wh, bdf, cur)
		if err != nil {
			return 0
		}
		if (c & 0xFF) == 0x10 {
			return cur
		}
		cur = (c >> 8) & 0xFF
	}
	return 0
}

// LinkSpeed reads the current PCIe link speed (gen).
func LinkSpeed(wh syscall.Handle, bdf uint32) uint32 {
	cap := PcieCap(wh, bdf)
	if cap == 0 {
		return 0
	}
	v, err := PciRd(wh, bdf, cap+0x12)
	if err != nil {
		return 0
	}
	return v & 0xF
}

// LinkWidth reads the current negotiated link width (lanes, 0=unknown).
// Also comes from LNKSTA: [9:4] = negotiated link width — the encoded
// value is the lane count (1/2/4/8/16/32). Both gen and width matter —
// "Gen2" ≠ full bandwidth; x8 is a slot / lane-allocation issue,
// unrelated to the unlock.
func LinkWidth(wh syscall.Handle, bdf uint32) uint32 {
	cap := PcieCap(wh, bdf)
	if cap == 0 {
		return 0
	}
	v, err := PciRd(wh, bdf, cap+0x12)
	if err != nil {
		return 0
	}
	return (v >> 4) & 0x3F
}

// FindRootPort finds the PCIe root port BDF on bus 0 whose secondary bus
// equals gpuBus.
func FindRootPort(wh syscall.Handle, gpuBus uint32) uint32 {
	for d := uint32(0); d < 32; d++ {
		for f := uint32(0); f < 8; f++ {
			bdf := (0 << 8) | (d << 3) | f
			id, err := PciRd(wh, bdf, 0x00)
			if err != nil || id == 0xFFFFFFFF || (id&0xFFFF) == 0 {
				continue
			}
			cls, _ := PciRd(wh, bdf, 0x08)
			if ((cls >> 16) & 0xFFFF) != 0x0604 {
				continue
			}
			sec, _ := PciRd(wh, bdf, 0x18)
			if ((sec >> 8) & 0xFF) == gpuBus {
				return bdf
			}
		}
	}
	return 0xFFFFFFFF
}
