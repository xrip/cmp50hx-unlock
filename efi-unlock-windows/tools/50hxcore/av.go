package hxcore

// Third-party antivirus detection (read-only) — used by the installer
// for scanning and diagnostics.
//
// Background: drivers such as WinRing0x64.sys / ThrottleStop.sys are not
// only blocked by Defender; third-party security products (Huorong / 360 /
// Tencent PC Manager, etc.) may quarantine them as well, and these products
// **do not read** the Defender exclusion list — the user must manually
// allow them via each product's trust/whitelist UI.
//
// This probe only identifies common third-party AVs by process name; it
// performs no modifications. "Not detected" does not mean "not present" —
// it simply means the product is outside the known list (informational
// only, not a security conclusion).
//
// Implementation: a single tasklist pulls everything; matching is done
// locally with lowercase substring checks (multiple process names per
// candidate).

import "strings"

type avCandidate struct {
	name  string
	procs []string // Match fragments (lowercase; process names may or may not have .exe)
}

var avCandidates = []avCandidate{
	{"Huorong Security", []string{"wsctrl", "hipsdaemon", "hipstray", "usysdiag", "huorong"}},
	{"360 Safe Guard / Antivirus", []string{"360tray", "360sd", "zhudongfangyu", "qhsafemon", "360safe"}},
	{"Tencent PC Manager", []string{"qqpctray", "qqpcrtp", "qqpc", "tencent pc manager"}},
	{"Kingsoft Antivirus", []string{"kxetray", "kxs", "kavsvc"}},
	{"2345 Safe Guard", []string{"2345safe", "safemon", "2345"}},
	{"Rising Antivirus", []string{"ravtask", "rav"}},
	{"Lenovo PC Manager", []string{"lenovopcmanager", "lenovo safe"}},
}

// DetectThirdPartyAV returns the list of detected third-party AV names
// (empty = no common third-party AV identified).
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
