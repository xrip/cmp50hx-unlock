package hxcore

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Gen2StatusPath returns %ProgramData%\50HXUnlock\gen2_status.txt.
// We pick ProgramData (not LOCALAPPDATA) because Gen2 is run by a
// SYSTEM scheduled task: SYSTEM's LOCALAPPDATA points to SystemProfile,
// which user-mode code cannot read. ProgramData is a system-wide common
// directory where SYSTEM can write and user-mode code can read — ideal
// for a "task → user" status channel.
func Gen2StatusPath() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "50HXUnlock", "gen2_status.txt")
}

// WriteGen2Status writes the Gen2 execution result into the status file
// (consumed by 40HXCheck). Silently fails on permission errors (does not
// affect the main unlock flow).
func WriteGen2Status(text string) error {
	p := Gen2StatusPath()
	os.MkdirAll(filepath.Dir(p), 0o755)
	head := "==== 50HX Gen2 task status " + time.Now().Format("2006-01-02 15:04:05") + " ====\n"
	return os.WriteFile(p, []byte(head+text+"\n"), 0o644)
}

// ReadGen2Status reads the status file; returns "" if missing/unreadable.
func ReadGen2Status() string {
	b, err := os.ReadFile(Gen2StatusPath())
	if err != nil {
		return ""
	}
	return string(b)
}

// ServiceInfo queries the kernel-driver service.
// Returns (exists?, start type DEMAND/AUTO/DISABLED, state RUNNING/STOPPED/...).
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
	// Start type needs sc qc.
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

// TaskInfo queries the scheduled task.
// v2.5.1 critical fix: handle Chinese-locale field names. The previous
// implementation only recognized English "status:" / "last result:" —
// but zh-CN output uses "模式:" / "上次结果:" (some versions "状态:"),
// which caused registered tasks to be misread as "not registered"; the
// community chased the false-positive diagnosis with repeated
// reinstalls (which is hard to tell apart from a truly missing task).
// Existence used to be decided by the schtasks exit code (non-existent
// task → exit 1), without depending on field parsing.
//
// v2.5.1 patch (root cause of still-misreported "not registered"):
// the above "use schtasks /query exit code as the sole existence
// criterion" can occasionally false-positive under Chinese locales /
// non-admin contexts — SYSTEM-owned tasks on some machines make
// /query exit non-zero (permissions / code page / transient service
// jitter) while the task XML file is already on disk. Changed to:
//   **Task XML file existence = authoritative proof of registration**;
//   schtasks /query only supplements the status / result fields.
// As long as the file is there, we declare it registered — this
// eliminates the false-negative "the task really is there but
// diagnostics say it isn't".
//
// Returns (exists?, state Ready/Running/Ready..., last run result
// "0" / "267011" / ...).
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
		// Some versions call the field "计划任务状态:" (Scheduled Task
		// State); fall back to that.
		if status == "" {
			for _, ln := range strings.Split(out, "\n") {
				t := strings.TrimSpace(ln)
				if strings.HasPrefix(t, "计划任务状态:") || strings.HasPrefix(strings.ToLower(t), "scheduled task state:") {
					status = strings.TrimSpace(t[strings.Index(t, ":")+1:])
					break
				}
			}
		}
		// Some versions write "上次运行结果:" differently — fall back to
		// plain "结果:".
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
	// Existence: schtasks gives explicit evidence, OR the task XML file
	// genuinely exists (authoritative proof). The file's presence is
	// enough — do not let schtasks exit-code jitter cause false reports.
	if status != "" || lastResult != "" ||
		strings.Contains(out, "TaskName") || strings.Contains(out, "任务名") ||
		taskXMLExists(name) {
		if status == "" {
			status = "registered"
		}
		return true, status, lastResult
	}
	return false, "", ""
}

// taskXMLExists uses the existence of %SystemRoot%\System32\Tasks\<name>
// as the authoritative proof of scheduled-task registration. A '\' in
// the task name denotes a subfolder (this tool's tasks live at the top
// level, so that case does not arise). This is the most reliable way to
// avoid schtasks /query exit-code races / permission false-positives.
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
