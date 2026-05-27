// Package sanitize strips malicious content from untrusted Discord messages
// before they are displayed in the terminal.
//
// Attack vectors defended against:
//   - ANSI/VT escape injection (terminal takeover, cursor manipulation, screen clear)
//   - OSC hyperlink injection (fake clickable links)
//   - DCS/APC/SOS/PM escape sequences
//   - Unicode bidirectional override attacks (source code spoofing)
//   - Zero-width and invisible characters
//   - Null bytes
package sanitize

// Sanitize runs the full sanitization pipeline on untrusted input from Discord.
// Safe to call on any string — returns a clean version suitable for terminal display.
func Sanitize(input string) string {
	input = stripANSI(input)       // Remove CSI, OSC, DCS, APC, RIS sequences
	input = stripBidi(input)       // Remove Unicode bidi control characters
	input = stripNulls(input)      // Remove null bytes (belt-and-suspenders)
	input = truncate(input, 4000)  // Hard limit on message length
	return input
}

// truncate shortens a string to at most maxRunes Unicode code points.
func truncate(s string, maxRunes int) string {
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	return string(runes[:maxRunes]) + "…"
}

// stripNulls removes null bytes from a string.
func stripNulls(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != 0x00 {
			out = append(out, s[i])
		}
	}
	return string(out)
}
