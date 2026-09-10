package hxcore

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Gen2StatusPath: %ProgramData%\50HXUnlock\gen2_status.txt
// 选 ProgramData(而非 LOCALAPPDATA) 是因为 Gen2 由 SYSTEM 计划任务执行:
// SYSTEM 的 LOCALAPPDATA 指向 SystemProfile, 用户态读不到; ProgramData 是
// 系统级公共目录, SYSTEM 可写、用户可读, 适合做"任务 → 用户"的状态通道。
func Gen2StatusPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "50HXUnlock", "gen2_status.txt")
}

// WriteGen2Status: Gen2 执行结果写入状态文件(供 40HXCheck 展示)。
// 权限不足时静默失败(不影响解锁主流程)。
func WriteGen2Status(text string) error {
	p := Gen2StatusPath()
	os.MkdirAll(filepath.Dir(p), 0o755)
	head := "==== 50HX Gen2 任务状态 " + time.Now().Format("2006-01-02 15:04:05") + " ====\n"
	return os.WriteFile(p, []byte(head+text+"\n"), 0o644)
}

// ReadGen2Status: 读状态文件; 不存在/读不到返回 ""
func ReadGen2Status() string {
	b, err := os.ReadFile(Gen2StatusPath())
	if err != nil {
		return ""
	}
	return string(b)
}

// ServiceInfo: 查询内核驱动服务。
// 返回 (是否存在, 启动类型 DEMAND/AUTO/DISABLED, 状态 RUNNING/STOPPED/…)
func ServiceInfo(name string) (bool, string, string) {
	out, err := RunOut("sc.exe", "query", name)
	if err != nil || !strings.Contains(out, "STATE") {
		return false, "", ""
	}
	state := "UNKNOWN"
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "STATE") {
			t := strings.ToUpper(strings.TrimSpace(ln))
			switch {
			case strings.Contains(t, "RUNNING"):
				state = "RUNNING"
			case strings.Contains(t, "STOPPED"):
				state = "STOPPED"
			case strings.Contains(t, "START_PENDING"):
				state = "START_PENDING"
			}
		}
	}
	// 启动类型需 sc qc
	stype := "UNKNOWN"
	if qc, err := RunOut("sc.exe", "qc", name); err == nil {
		t := strings.ToUpper(qc)
		switch {
		case strings.Contains(t, "DEMAND_START"):
			stype = "DEMAND"
		case strings.Contains(t, "AUTO_START"):
			stype = "AUTO"
		case strings.Contains(t, "DISABLED"):
			stype = "DISABLED"
		case strings.Contains(t, "BOOT_START"):
			stype = "BOOT"
		case strings.Contains(t, "SYSTEM_START"):
			stype = "SYSTEM"
		}
	}
	return true, stype, state
}

// TaskInfo: 查询计划任务。
// v2.5.1 关键修复: 兼容中文系统字段名。此前只认英文 "status:"/"last result:",
// 而 zh-CN 输出是 "模式:"/"上次结果:"(部分版本为 "状态:") — 导致已注册任务
// 被误判"未注册", 社区拿着误报诊断反复重装(与真实未注册难以区分)。
// 存在性以退出码为准(不存在时 schtasks 退出码 1), 不依赖字段解析。
// 返回 (是否存在, 状态 Ready/Running/已就绪…, 上次运行结果 "0"/"267011"…)
//
// v2.5.1 补丁(诊断仍误报"未注册"根因): 上述以 schtasks /query 退出码为唯一存在性
// 判据在中文/非管理员环境下会偶发误报——SYSTEM 主体的任务在部分机器上 /query 退出
// 非零(权限/代码页/瞬时服务抖动), 而任务 XML 文件其实已落盘。故改为:
//   **任务 XML 文件存在 = 权威存在性铁证**; schtasks /query 仅补充状态/结果字段。
// 只要文件在, 即判定已注册, 彻底消除"任务真在却诊断说没注册"的假阴性。
func TaskInfo(name string) (bool, string, string) {
	out, err := RunOut("schtasks.exe", "/query", "/tn", name, "/fo", "LIST", "/v")
	status, lastResult := "", ""
	if err == nil || out != "" {
		for _, ln := range strings.Split(out, "\n") {
			t := strings.TrimSpace(ln)
			low := strings.ToLower(t)
			switch {
			case strings.HasPrefix(low, "status:"),
				strings.HasPrefix(t, "模式:"), strings.HasPrefix(t, "状态:"):
				status = strings.TrimSpace(t[strings.Index(t, ":")+1:])
			case strings.HasPrefix(low, "last result:"),
				strings.HasPrefix(t, "上次结果:"), strings.HasPrefix(t, "上次运行结果:"):
				lastResult = strings.TrimSpace(t[strings.Index(t, ":")+1:])
			}
		}
		// 状态字段个别版本叫 "计划任务状态:"(Scheduled Task State), 兜底采用
		if status == "" {
			for _, ln := range strings.Split(out, "\n") {
				t := strings.TrimSpace(ln)
				if strings.HasPrefix(t, "计划任务状态:") || strings.HasPrefix(strings.ToLower(t), "scheduled task state:") {
					status = strings.TrimSpace(t[strings.Index(t, ":")+1:])
					break
				}
			}
		}
		// 个别版本 "上次运行结果:" 之外的写法, 按 "结果:" 兜底
		if lastResult == "" {
			for _, ln := range strings.Split(out, "\n") {
				t := strings.TrimSpace(ln)
				if i := strings.Index(t, "结果:"); i >= 0 {
					lastResult = strings.TrimSpace(t[i+len("结果:"):])
					break
				}
			}
		}
	}
	// 存在性: schtasks 给出明确证据, 或任务 XML 文件真实存在(权威铁证)。
	// 文件存在即判定已注册, 不因 schtasks 退出码波动而误报。
	if status != "" || lastResult != "" ||
		strings.Contains(out, "TaskName") || strings.Contains(out, "任务名") ||
		taskXMLExists(name) {
		if status == "" {
			status = "已注册"
		}
		return true, status, lastResult
	}
	return false, "", ""
}

// taskXMLExists: 以 %SystemRoot%\System32\Tasks\<任务名> 文件存在性作为
// 计划任务已注册的权威判据。任务名中的 '\' 表示子文件夹(本工具任务为顶层, 无此情况)。
// 这是避开 schtasks /query 退出码竞态/权限误报的最可靠方式。
func taskXMLExists(name string) bool {
	sysroot := os.Getenv("SystemRoot")
	if sysroot == "" {
		sysroot = `C:\Windows`
	}
	p := filepath.Join(sysroot, "System32", "Tasks", name)
	if _, e := os.Stat(p); e == nil {
		return true
	}
	return false
}
