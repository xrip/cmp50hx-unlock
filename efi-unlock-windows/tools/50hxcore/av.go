package hxcore

// 第三方杀软探测(只读) — 供安装器扫描与诊断使用。
//
// 背景: WinRing0x64.sys / ThrottleStop.sys 这类驱动不仅会被 Defender 拦,
// 第三方安全软件(火绒/360/腾讯管家等)同样可能隔离, 而且它们**不读**
// Defender 的排除列表 — 只能靠用户在其信任/白名单里手动放行。
// 本探测只按进程名识别常见第三方安全软件, 不做任何修改; 识别不到 ≠ 没有,
// 只是超出已知清单(仅供提示, 不构成安全结论)。
//
// 实现: tasklist 一次全量抓取, 本地做小写包含匹配(每个候选多个进程名)。

import "strings"

type avCandidate struct {
	name  string
	procs []string // 匹配片段(小写; 进程名可带/可不带 .exe)
}

var avCandidates = []avCandidate{
	{"火绒安全 (Huorong)", []string{"wsctrl", "hipsdaemon", "hipstray", "usysdiag", "huorong"}},
	{"360 安全卫士/杀毒", []string{"360tray", "360sd", "zhudongfangyu", "qhsafemon", "360safe"}},
	{"腾讯电脑管家", []string{"qqpctray", "qqpcrtp", "qqpc", "tencent pc manager"}},
	{"金山毒霸", []string{"kxetray", "kxs", "kavsvc"}},
	{"2345 安全卫士", []string{"2345safe", "safemon", "2345"}},
	{"瑞星", []string{"ravtask", "rav"}},
	{"联想电脑管家", []string{"lenovopcmanager", "lenovo safe"}},
}

// DetectThirdPartyAV: 返回识别到的第三方杀软名列表(空 = 未识别到常见第三方)。
func DetectThirdPartyAV() []string {
	out, err := RunOut("tasklist.exe", "/fo", "csv", "/nh")
	if err != nil {
		return nil
	}
	low := strings.ToLower(out)
	var found []string
	for _, cand := range avCandidates {
		for _, p := range cand.procs {
			if strings.Contains(low, p) {
				found = append(found, cand.name)
				break
			}
		}
	}
	return found
}
