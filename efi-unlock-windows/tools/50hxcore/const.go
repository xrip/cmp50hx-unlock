// 50hxcore — CMP 50HX 解锁工具链共享核心(只读探测 + 寄存器访问)
//
// 由 tools/inst50hx(main) 与 tools/check50x(50HXCheck.exe) 共同引用,
// 保证"诊断逻辑只有一份实现, 不会两处漂移"。常量与源码与
// inst50hx/main.go 同步维护 — 改动任一侧需同步另一侧。
package hxcore

const (
	// 50HX PCI 硬件 ID (伪装驱动改不了它 — v2.4.2 反查的根基)
	GpuVenDev = "VEN_10DE&DEV_1E09"

	// 显示适配器 Class 注册表路径与子键值
	GpuClassPath  = `SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}`
	GpuClassGUID  = `{4d36e968-e325-11ce-bfc1-08002be10318}` // Enum Driver 值反查用
	GpuEnableFw   = "EnableGpuFirmware"                     // GSP 启用开关 (=1)
	GpuAdapterStr = "HardwareInformation.AdapterString"     // 驱动真实卡名(伪装也改不了此路径)
	GpuAdapter40  = "CMP 50HX"

	// PCI 设备枚举根 (含 50HX 的 VEN_10DE&DEV_1E09 节点)
	GpuEnumBase = `SYSTEM\CurrentControlSet\Enum\PCI`
)
