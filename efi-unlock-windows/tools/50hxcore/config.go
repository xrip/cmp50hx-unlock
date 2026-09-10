package hxcore

import (
	"golang.org/x/sys/windows/registry"
)

// v2.6.0: Gen2 运行策略配置中心 (HKLM\SOFTWARE\50HXUnlock)。
// GUI 策略页与 CLI 都只读写这里; -gen2 每次启动时读取。
// 全部键缺省即合理默认(用完即卸 + 自动 Stage2 + 失败自动重试 3 次/1 分钟,
// v3.0.1 起间隔默认 1 分钟); 键缺失时用这些默认值。

const ConfigKeyPath = `SOFTWARE\50HXUnlock`

// 驱动运行策略 (DriverStrategy)
const (
	DriverStrategyTransient = 0 // 用完即卸(默认): 解锁后停服务+删文件, 反作弊干净
	DriverStrategyWatchdog  = 1 // 失败自动重试(旧名"看门狗"): 失败按下方节奏自动再试, 成功后仍卸
	DriverStrategyResident  = 2 // 常驻守护(v3.0.1): 服务保持加载 + 登录任务每分钟自查 Gen2, TLS 丢失自动重训
)

// ConfigInt: 读 DWORD 配置, 不存在/读不到返回 def
func ConfigInt(name string, def int) int {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ConfigKeyPath, registry.QUERY_VALUE)
	if err != nil {
		return def
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return def
	}
	return int(v)
}

// SetConfigInt: 写 DWORD 配置(键不存在自动创建); GUI 策略页用
func SetConfigInt(name string, val int) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, ConfigKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, uint32(val))
}

// DriverStrategy: 当前驱动运行策略(越界回退用完即卸)。
// v2.6.1: 已移除"仅部署"(3) — 注册表若残留旧值 3, 一律回到默认"用完即卸"。
func DriverStrategy() int {
	v := ConfigInt("DriverStrategy", DriverStrategyTransient)
	if v == 3 {
		return DriverStrategyTransient
	}
	if v < DriverStrategyTransient {
		return DriverStrategyTransient
	}
	if v > DriverStrategyResident {
		return DriverStrategyResident
	}
	return v
}

// Gen2RetryPolicy: 失败自动重试次数与间隔分钟。
// 默认 3 次 / 1 分钟(v3.0.1 起间隔默认 1 分钟)。
func Gen2RetryPolicy() (count, intervalMin int) {
	count = configIntClamped("Gen2RetryCount", 3, 0, 12)
	intervalMin = configIntClamped("Gen2RetryIntervalMin", 1, 1, 240)
	return count, intervalMin
}

func configIntClamped(name string, def, min, max int) int {
	v := ConfigInt(name, def)
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// DeleteConfig: 卸载时删除整个策略键 (HKLM\SOFTWARE\50HXUnlock)。
// 键不存在视为成功(卸载幂等); 删除后重装即回到全部默认值,
// 避免"曾设常驻/改过重试 → 卸载重装后仍继承旧策略"的状态残留。
func DeleteConfig() {
	registry.DeleteKey(registry.LOCAL_MACHINE, ConfigKeyPath)
}
