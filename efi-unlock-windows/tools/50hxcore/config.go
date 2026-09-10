package hxcore

import (
	"golang.org/x/sys/windows/registry"
)

// v2.6.0: Gen2 runtime policy configuration hub (HKLM\SOFTWARE\50HXUnlock).
// The GUI policy page and the CLI both read/write only here; -gen2 reads
// from here on every start. Missing keys fall back to reasonable defaults
// (remove-when-done + automatic Stage2 + auto-retry on failure 3 times per
// 1 minute; since v3.0.1 the default interval is 1 minute).

const ConfigKeyPath = `SOFTWARE\50HXUnlock`

// Driver runtime strategy (DriverStrategy)
const (
	DriverStrategyTransient = 0 // Remove-when-done (default): stop service + delete files after unlock; clean against anti-cheat
	DriverStrategyWatchdog  = 1 // Auto-retry on failure (legacy "watchdog"): retry on failure using the schedule below; still remove on success
	DriverStrategyResident  = 2 // Resident guardian (v3.0.1): service stays loaded + a logon task re-checks Gen2 every minute; auto-retrains if TLS is lost
)

// ConfigInt reads a DWORD config value; returns def if missing/unreadable.
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

// SetConfigInt writes a DWORD config value (key is created if missing);
// used by the GUI policy page.
func SetConfigInt(name string, val int) error {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, ConfigKeyPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetDWordValue(name, uint32(val))
}

// DriverStrategy returns the current driver runtime strategy
// (out-of-range values fall back to remove-when-done).
// v2.6.1: "Deploy-only" (3) was removed — if the registry still carries
// the legacy value 3, it is always coerced back to the default
// remove-when-done.
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

// Gen2RetryPolicy returns the failure-retry count and the interval (minutes).
// Default: 3 retries / 1 minute (since v3.0.1 the default interval is 1 minute).
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

// DeleteConfig removes the entire policy key (HKLM\SOFTWARE\50HXUnlock)
// on uninstall. A missing key counts as success (idempotent uninstall);
// after deletion, a reinstall returns to all defaults, avoiding
// stale-state carry-over such as "used to be resident/changed retry →
// still inherits the old policy after reinstall".
func DeleteConfig() {
	registry.DeleteKey(registry.LOCAL_MACHINE, ConfigKeyPath)
}
