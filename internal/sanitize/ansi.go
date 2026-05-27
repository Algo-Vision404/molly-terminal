package sanitize

import "regexp"

// These patterns cover all known ANSI/VT escape categories.
//
// Reference: ECMA-48, XTerm control sequences.
//
// CSI sequences: ESC [ <params> <final byte 0x40–0x7E>
//   Examples: \x1b[2J (clear screen), \x1b[H (cursor home), \x1b[?1049h (alt screen)
//
// OSC sequences: ESC ] <anything> (ST | BEL)
//   Examples: \x1b]8;;https://evil.com\x07 (hyperlink injection)
//
// DCS sequences: ESC P <anything> ST
//   Used for terminal programming — always strip.
//
// APC/PM/SOS: ESC _ / ESC ^ / ESC X <anything> ST
//   Private-use and rarely benign — always strip.
//
// RIS: ESC c — resets the entire terminal. Highly destructive.
//
// Character set designations: ESC ( <char> — can break terminal rendering.
//
// SS2/SS3, single-char escapes: strip any ESC followed by a byte 0x40–0x5F
//   that isn't the start of a two-byte sequence we already handle.
var (
	// CSI: ESC [ ... <final 0x40–0x7E>
	// Handles optional intermediate bytes (0x20–0x2F) and parameter bytes (0x30–0x3F).
	csiPattern = regexp.MustCompile(`\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]`)

	// OSC: ESC ] ... (BEL or ST)
	// ST = ESC \  (two bytes)
	oscPattern = regexp.MustCompile(`\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)`)

	// DCS: ESC P ... ST
	dcsPattern = regexp.MustCompile(`\x1b[P][^\x1b]*(?:\x1b\\)`)

	// APC: ESC _ ... ST
	apcPattern = regexp.MustCompile(`\x1b[_][^\x1b]*(?:\x1b\\)`)

	// PM: ESC ^ ... ST
	pmPattern = regexp.MustCompile(`\x1b[\^][^\x1b]*(?:\x1b\\)`)

	// SOS: ESC X ... ST
	sosPattern = regexp.MustCompile(`\x1b[X][^\x1b]*(?:\x1b\\)`)

	// Character set designation: ESC ( <any> or ESC ) <any>
	charsetPattern = regexp.MustCompile(`\x1b[()][^\x1b]`)

	// RIS (Reset to Initial State) and other single-byte ESC sequences:
	// ESC followed by a byte in 0x40–0x5F (excludes [ P _ ^ X which are multi-byte).
	// This catches: ESC c (RIS), ESC M (reverse index), ESC 7/8 (save/restore cursor), etc.
	risPattern = regexp.MustCompile(`\x1b[\x40-\x5f]`)

	// Catch-all: any remaining bare ESC that we haven't handled.
	bareEscPattern = regexp.MustCompile(`\x1b.?`)
)

// stripANSI removes all ANSI/VT escape sequences from s.
// Applies patterns in order from most specific to most general.
func stripANSI(s string) string {
	s = csiPattern.ReplaceAllString(s, "")
	s = oscPattern.ReplaceAllString(s, "")
	s = dcsPattern.ReplaceAllString(s, "")
	s = apcPattern.ReplaceAllString(s, "")
	s = pmPattern.ReplaceAllString(s, "")
	s = sosPattern.ReplaceAllString(s, "")
	s = charsetPattern.ReplaceAllString(s, "")
	s = risPattern.ReplaceAllString(s, "")
	// Final pass: remove any lingering ESC bytes (e.g. truncated sequences).
	s = bareEscPattern.ReplaceAllString(s, "")
	return s
}
