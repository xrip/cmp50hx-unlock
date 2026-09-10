// 50hxcore — shared core for the CMP 50HX unlock toolchain
// (read-only probing + register access).
//
// Imported by tools/inst50hx (main) and tools/check50x (50HXCheck.exe) to
// guarantee that "diagnostic logic has a single implementation and does not
// drift across both copies." Constants and source are kept in sync with
// inst50hx/main.go — changes on either side must be mirrored on the other.
package hxcore

const (
	// 50HX PCI hardware ID (cannot be changed by a disguising driver — root
	// of the v2.4.2 reverse-lookup).
	GpuVenDev = "VEN_10DE&DEV_1E09"

	// Display adapters Class registry path and sub-key values.
	GpuClassPath  = `SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}`
	GpuClassGUID  = `{4d36e968-e325-11ce-bfc1-08002be10318}` // Used for the Enum Driver value reverse-lookup
	GpuEnableFw   = "EnableGpuFirmware"                     // GSP enable switch (=1)
	GpuAdapterStr = "HardwareInformation.AdapterString"     // Driver-reported card name (the disguising driver cannot change this path either)
	GpuAdapter40  = "CMP 50HX"

	// PCI device enumeration root (contains the VEN_10DE&DEV_1E09 node for 50HX).
	GpuEnumBase = `SYSTEM\CurrentControlSet\Enum\PCI`
)
