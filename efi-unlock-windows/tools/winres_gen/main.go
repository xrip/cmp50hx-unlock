// winres_gen: one-shot generator for the inst50hx .syso resource
// (comctl32 v6 manifest + version info). walk requires the v6 manifest
// for modern control visuals. Usage: go run . <out.syso path>
package main

import (
	"fmt"
	"os"

	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: winres_gen <out.syso>")
		os.Exit(1)
	}
	rs := winres.ResourceSet{}
	am := winres.AppManifest{
		Identity:            winres.AssemblyIdentity{Name: "40HX.Installer", Version: [4]uint16{3, 0, 0, 0}},
		Description:         "CMP 50HX Unlock Manager (compute unlock + PCIe Gen2)",
		UseCommonControlsV6: true,
		DPIAwareness:        winres.DPIPerMonitorV2,
		ExecutionLevel:      winres.AsInvoker,
	}
	rs.SetManifest(am)
	vi := version.Info{}
	vi.SetFileVersion("3.0.0.0")
	vi.SetProductVersion("3.0.0.0")
	vi.Set(winres.LCIDDefault, "ProductName", "CMP 50HX Windows Unlock")
	vi.Set(winres.LCIDDefault, "FileDescription", "50HX Installer/Manager")
	vi.Set(winres.LCIDDefault, "LegalCopyright", "For personal hardware research and learning use only")
	vi.Set(winres.LCIDDefault, "OriginalFilename", "50HXInstaller.exe")
	rs.SetVersionInfo(vi)
	f, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := rs.WriteObject(f, winres.ArchAMD64); err != nil {
		panic(err)
	}
	fmt.Println("written:", os.Args[1])
}