package hxcore

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// FindGpuClassKey: 定位 50HX 的显示适配器 Class 子键 (0000/0001/...)
// 返回子键完整路径; 找不到返回 ""。
//
// v2.4.2 重写 — 不再依赖 AdapterString 名字匹配!
// 伪装驱动(社区魔改把 50HX 显示成 RTX 2070/2060S 等)只能改
// AdapterString/FriendlyName/DeviceDesc, 改不了 PCI 硬件 ID 与 Enum 节点
// 的 Driver 值。正解 = 从 Enum\PCI\VEN_10DE&DEV_1E09\*\* 的 Driver 值
// (形如 "{4d36e968-...}\0001") 反查 Class 子键, 与卡名无关。
// 名字匹配(AdapterString 含 CMP 50HX / 2070 / 2060S)仅作 Enum 缺失兜底。
func FindGpuClassKey() string {
	if key := findGpuClassKeyByEnum(); key != "" {
		return key
	}
	return findGpuClassKeyByName()
}

// findGpuClassKeyByEnum: 遍历 Enum\PCI 下 VEN_10DE&DEV_1E09 各实例,
// 读 Driver 值 "{classGUID}\000x" → 拼接成 Class 路径返回。
// 伪装驱动(2070/2060S)不影响此路径。
func findGpuClassKeyByEnum() string {
	base, err := registry.OpenKey(registry.LOCAL_MACHINE, GpuEnumBase,
		registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return ""
	}
	defer base.Close()
	devs, err := base.ReadSubKeyNames(-1)
	if err != nil {
		return ""
	}
	for _, d := range devs {
		if !strings.Contains(d, GpuVenDev) {
			continue
		}
		dk, err := registry.OpenKey(registry.LOCAL_MACHINE, GpuEnumBase+`\`+d,
			registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		insts, _ := dk.ReadSubKeyNames(-1)
		dk.Close()
		for _, inst := range insts {
			ik, err := registry.OpenKey(registry.LOCAL_MACHINE,
				GpuEnumBase+`\`+d+`\`+inst, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			drv, _, _ := ik.GetStringValue("Driver")
			ik.Close()
			// Driver = "{4d36e968-e325-11ce-bfc1-08002be10318}\0001"
			if strings.Contains(drv, GpuClassGUID) {
				sub := drv[strings.LastIndex(drv, `\`)+1:]
				return GpuClassPath + `\` + sub
			}
		}
	}
	return ""
}

// findGpuClassKeyByName: 名字匹配兜底。伪装驱动时 AdapterString 可能是
// "NVIDIA GeForce RTX 2070"/"2060 SUPER" 等 → 这些名字也要认。
// 仅当 Enum 反查失败才走这里(正常不会)。
func findGpuClassKeyByName() string {
	alias := []string{GpuAdapter40, "2070", "2060", "2060 SUPER", "2060 super"}
	base, err := registry.OpenKey(registry.LOCAL_MACHINE, GpuClassPath,
		registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return ""
	}
	defer base.Close()
	names, err := base.ReadSubKeyNames(-1)
	if err != nil {
		return ""
	}
	for _, n := range names {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, GpuClassPath+`\`+n,
			registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		adapter, _, _ := k.GetStringValue(GpuAdapterStr)
		desc, _, _ := k.GetStringValue("DriverDesc")
		// 伪装驱动可能只改 DriverDesc(设备管理器显示名)
		hay := adapter + " " + desc
		k.Close()
		for _, a := range alias {
			if strings.Contains(hay, a) {
				return GpuClassPath + `\` + n
			}
		}
	}
	return ""
}

// GspEnabled: 读当前 EnableGpuFirmware (1=开, 0/缺省=关)
func GspEnabled() bool {
	key := FindGpuClassKey()
	if key == "" {
		return false
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(GpuEnableFw)
	return err == nil && v == 1
}

// GspDiag: 诊断 — 返回 (匹配到的子键短名, 该键 AdapterString/DriverDesc,
// EnableGpuFirmware 值)。找不到时 sub="" 且第二返回值是"全部子键列表"诊断串。
// 伪装/魔改驱动(识别成 2070 等)不影响 Enum 反查; 此函数便于展示真实键位。
func GspDiag() (string, string, int64) {
	key := findGpuClassKeyByEnum()
	if key == "" {
		key = findGpuClassKeyByName()
	}
	if key == "" {
		var sb strings.Builder
		base, err := registry.OpenKey(registry.LOCAL_MACHINE, GpuClassPath,
			registry.ENUMERATE_SUB_KEYS)
		if err == nil {
			defer base.Close()
			names, _ := base.ReadSubKeyNames(-1)
			for _, n := range names {
				k, err := registry.OpenKey(registry.LOCAL_MACHINE, GpuClassPath+`\`+n,
					registry.QUERY_VALUE)
				if err != nil {
					continue
				}
				adapter, _, _ := k.GetStringValue(GpuAdapterStr)
				desc, _, _ := k.GetStringValue("DriverDesc")
				k.Close()
				if adapter != "" || desc != "" {
					sb.WriteString(n + "=" + adapter + "/" + desc + " | ")
				}
			}
		}
		return "", "(无 50HX 匹配! 实际子键: " + sb.String() + ")", -1
	}
	sub := key[strings.LastIndex(key, `\`)+1:]
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return sub, "(读取失败)", -1
	}
	defer k.Close()
	adapter, _, _ := k.GetStringValue(GpuAdapterStr)
	if adapter == "" {
		adapter, _, _ = k.GetStringValue("DriverDesc")
	}
	fw, _, fwErr := k.GetIntegerValue(GpuEnableFw)
	v := int64(-1)
	if fwErr == nil {
		v = int64(fw)
	}
	return sub, adapter, v
}
