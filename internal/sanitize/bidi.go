package sanitize

import "strings"

// bidiControls contains Unicode code points that can be used to manipulate
// text rendering direction, making malicious content appear benign.
//
// Notable attacks:
//   - RLO (U+202E): "// safe comment \u202Eniamretxe" appears to end with ".exe"
//   - Invisible characters used to hide content from reviewers
//
// References:
//   - CVE-2021-42574 (Trojan Source)
//   - https://trojansource.codes/
var bidiControls = []rune{
	'\u202A', // LEFT-TO-RIGHT EMBEDDING
	'\u202B', // RIGHT-TO-LEFT EMBEDDING
	'\u202C', // POP DIRECTIONAL FORMATTING
	'\u202D', // LEFT-TO-RIGHT OVERRIDE
	'\u202E', // RIGHT-TO-LEFT OVERRIDE ← most dangerous (Trojan Source)
	'\u2066', // LEFT-TO-RIGHT ISOLATE
	'\u2067', // RIGHT-TO-LEFT ISOLATE
	'\u2068', // FIRST STRONG ISOLATE
	'\u2069', // POP DIRECTIONAL ISOLATE
	'\u200E', // LEFT-TO-RIGHT MARK
	'\u200F', // RIGHT-TO-LEFT MARK
	'\uFEFF', // ZERO WIDTH NO-BREAK SPACE (BOM — confusing when mid-string)
	'\u200B', // ZERO WIDTH SPACE
	'\u2060', // WORD JOINER
	'\u200C', // ZERO WIDTH NON-JOINER
	'\u200D', // ZERO WIDTH JOINER
}

// buildBidiReplacer constructs a strings.Replacer that removes all bidi controls.
// Called once at package init to avoid repeated construction.
var bidiReplacer = func() *strings.Replacer {
	pairs := make([]string, 0, len(bidiControls)*2)
	for _, r := range bidiControls {
		pairs = append(pairs, string(r), "")
	}
	return strings.NewReplacer(pairs...)
}()

// stripBidi removes all Unicode bidirectional control characters from s.
func stripBidi(s string) string {
	return bidiReplacer.Replace(s)
}
