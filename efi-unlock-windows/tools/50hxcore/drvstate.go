package hxcore

// Gen2 BYOVD 驱动的"部署/安装状态"结构化检测 — 供 GUI 页①扫描 / 页②预勾选 /
// 安装器 -status / 诊断工具共用, 消除各处"看文件在不在"的拍脑袋判定。
//
// 部署模型 (v2.5 起):
//   1. 持久备份源  %ProgramData%\50HXUnlock\drivers\*.sys
//      - installDrivers 每次部署都会写; cleanupByovd(用完即卸)不删它
//      - 因此它是"曾部署过"的持久证据, 只有卸载器才删
//   2. 瞬态部署    %SystemRoot%\System32\drivers\*.sys + demand 内核服务
//      - "用完即卸"(S0)/"看门狗"(S1)成功后文件与服务被自清理 →
//        文件缺失 ≠ 未安装! 要看备份源与当前策略才能下结论
//   3. Defender 排除(两个 .sys + ProgramData 备份目录) — 防杀软误删
//
// 文件有效性规则:
//   - 0 字节文件 = 杀软隔离占位(存在但不能算已部署)
//   - System32 文件大小与备份源不一致 = 被替换/损坏(需重部署)
//   - 服务被第三方/安全软件改成 DISABLED = Gen2 永远拉不起来(需提示修复)
//   - demand 服务平时 STOPPED 属正常(登录任务才拉起), 不算失败

import (
	"os"
	"path/filepath"
)

// DrvState: System32 驱动文件的四态
type DrvState int

const (
	DrvAbsent       DrvState = iota // 不存在
	DrvZero                         // 存在但 0 字节 — 杀软隔离占位
	DrvOk                           // 存在且 >0
	DrvSizeMismatch                 // 存在且 >0, 但与备份源大小不一致
)

func (s DrvState) String() string {
	switch s {
	case DrvZero:
		return "0字节(疑似杀软隔离)"
	case DrvOk:
		return "OK"
	case DrvSizeMismatch:
		return "大小与备份不一致"
	default:
		return "缺失"
	}
}

// DrvDeploy: 单个 Gen2 驱动的完整部署状态
type DrvDeploy struct {
	Service    string   // 服务名 ThrottleStop / WinRing0_1_2_0
	File       string   // 文件名 ThrottleStop.sys / WinRing0x64.sys
	BackupOK   bool     // %ProgramData%\50HXUnlock\drivers 备份源存在且 >0
	SysState   DrvState // System32 文件状态
	SysSize    int64
	SvcReg     bool   // 服务已注册
	SvcStart   string // DEMAND/AUTO/DISABLED/BOOT/SYSTEM/UNKNOWN
	SvcRunning bool   // 当前 RUNNING
}

type gen2Spec struct{ svc, file string }

var gen2Specs = []gen2Spec{
	{"ThrottleStop", "ThrottleStop.sys"},
	{"WinRing0_1_2_0", "WinRing0x64.sys"},
}

// PdDrvDir: %ProgramData%\50HXUnlock\drivers (安装器写入的持久备份源)
func PdDrvDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "50HXUnlock", "drivers")
}

func sysRoot() string {
	if r := os.Getenv("SystemRoot"); r != "" {
		return r
	}
	return `C:\Windows`
}

// InspectGen2Drivers: 逐一检查两个 Gen2 驱动: 备份源 / System32 文件 / 服务。
// 全部为只读探测(sc query/qc/stat), 无任何副作用。
func InspectGen2Drivers() []DrvDeploy {
	out := make([]DrvDeploy, 0, len(gen2Specs))
	for _, sp := range gen2Specs {
		d := DrvDeploy{Service: sp.svc, File: sp.file}
		bp := filepath.Join(PdDrvDir(), sp.file)
		if st, _ := fileState(bp); st == DrvOk {
			d.BackupOK = true
		}
		spath := filepath.Join(sysRoot(), "System32", "drivers", sp.file)
		st, sz := fileState(spath)
		d.SysState, d.SysSize = st, sz
		if st == DrvOk && d.BackupOK {
			if fi, err := os.Stat(bp); err == nil && fi.Size() != sz {
				d.SysState = DrvSizeMismatch
			}
		}
		if reg, start, state := ServiceInfo(sp.svc); reg {
			d.SvcReg = true
			d.SvcStart = start
			d.SvcRunning = state == "RUNNING"
		}
		out = append(out, d)
	}
	return out
}

// Gen2DriversDeployedOnce: 备份源是否存在 = "安装器是否部署过"的持久证据
// (System32 文件会被"用完即卸"清掉, 不能用它判断是否装过)。
func Gen2DriversDeployedOnce() bool {
	for _, sp := range gen2Specs {
		if st, _ := fileState(filepath.Join(PdDrvDir(), sp.file)); st == DrvOk {
			return true
		}
	}
	return false
}

// Gen2DriversNeedDeploy: 页②预勾选判据 — 出现下列任一情况才需要(重新)部署:
//   从未部署(备份源无) / 服务被 DISABLED / System32 文件 0 字节或与备份不一致。
// "用完即卸"后 System32 缺失但备份源在 → 不需要部署(登录任务会自动重放)。
func Gen2DriversNeedDeploy() bool {
	if !Gen2DriversDeployedOnce() {
		return true
	}
	for _, d := range InspectGen2Drivers() {
		if d.SvcReg && d.SvcStart == "DISABLED" {
			return true
		}
		if d.SysState == DrvZero || d.SysState == DrvSizeMismatch {
			return true
		}
	}
	return false
}

func fileState(p string) (DrvState, int64) {
	fi, err := os.Stat(p)
	if err != nil {
		return DrvAbsent, 0
	}
	if fi.Size() == 0 {
		return DrvZero, 0
	}
	return DrvOk, fi.Size()
}

