// winres_gen: 一次性生成 inst50hx 的 .syso 资源(comctl32 v6 清单 + 版本信息)。
// walk 需要 v6 清单才有现代控件外观。用法: go run . <输出.syso 路径>
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
	vi.Set(winres.LCIDDefault, "LegalCopyright", "仅供个人硬件研究与学习使用")
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