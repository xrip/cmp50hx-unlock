package hxcore

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// FindGpuClassKey locates the 50HX display-adapter Class subkey
// (0000/0001/...). Returns the full subkey path, or "" if not found.
//
// v2.4.2 rewrite — no longer relies on AdapterString name matching!
// Disguising drivers (community mods that make the 50HX appear as an
// RTX 2070 / 2060S, etc.) can only change AdapterString / FriendlyName /
// DeviceDesc — they cannot touch the PCI hardware ID or the Enum-node
// Driver value. The correct path: reverse-lookup the Class subkey from
// the Driver value (e.g. "{4d36e968-...}\0001") of
// Enum\PCI\VEN_10DE&DEV_1E09\*\*, independent of the card name. The
// name match (AdapterString containing CMP 50HX / 2070 / 2060S) is only a
// fallback for when the Enum reverse-lookup is missing.
func FindGpuClassKey() string {
	if key := findGpuClassKeyByEnum(); key != "" {
		return key
	}
	return findGpuClassKeyByName()
}

// findGpuClassKeyByEnum walks each VEN_10DE&DEV_1E09 instance under
// Enum\PCI, reads the Driver value "{classGUID}\000x", then composes
// the Class path. Disguising drivers (2070 / 2060S) do not affect this path.
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

// findGpuClassKeyByName is the name-matching fallback. A disguising
// driver may set AdapterString to "NVIDIA GeForce RTX 2070" /
// "2060 SUPER", etc. — those names must also be recognized.
// Only used when the Enum reverse-lookup fails (which is not normal).
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
		// A disguising driver may only override DriverDesc (the
		// Device Manager display name).
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

// GspEnabled reads the current EnableGpuFirmware value (1=on, 0/missing=off).
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

// GspDiag is the diagnostic helper — returns (matched subkey short name,
// the AdapterString/DriverDesc at that key, the EnableGpuFirmware value).
// When nothing matches, sub="" and the second return is a diagnostic
// "complete subkey listing" string. Disguising / modded drivers (the card
// appearing as 2070 etc.) do not affect the Enum reverse-lookup; this
// function makes it easy to show the real key location.
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
		return "", "(no 50HX match! Actual subkeys: " + sb.String() + ")", -1
	}
	sub := key[strings.LastIndex(key, `\`)+1:]
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, key, registry.QUERY_VALUE)
	if err != nil {
		return sub, "(read failed)", -1
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
