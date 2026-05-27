package sanitize

import (
	"strings"
	"testing"
)

func TestSanitize_ANSIStripping(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string // substring that must NOT appear in output
		clean string // expected output (if exact match needed)
	}{
		{
			name:  "clear screen",
			input: "\x1b[2J\x1b[H",
			want:  "\x1b",
		},
		{
			name:  "alternate screen buffer",
			input: "\x1b[?1049h enter alt screen \x1b[?1049l",
			want:  "\x1b",
		},
		{
			name:  "OSC hyperlink injection",
			input: "\x1b]8;;https://evil.com\x07click me\x1b]8;;\x07",
			want:  "\x1b",
		},
		{
			name:  "OSC hyperlink with ST terminator",
			input: "\x1b]8;;https://evil.com\x1b\\click me\x1b]8;;\x1b\\",
			want:  "\x1b",
		},
		{
			name:  "RIS full terminal reset",
			input: "before\x1bcafter",
			want:  "\x1b",
		},
		{
			name:  "cursor manipulation",
			input: "\x1b[10;5H text at position",
			want:  "\x1b",
		},
		{
			name:  "SGR color codes stripped",
			input: "\x1b[31mred text\x1b[0m",
			want:  "\x1b",
		},
		{
			name:  "window title injection via OSC",
			input: "\x1b]0;malicious title\x07",
			want:  "\x1b",
		},
		{
			name:  "plain text preserved",
			input: "hello world",
			clean: "hello world",
		},
		{
			name:  "emoji preserved",
			input: "hello 🎉 world",
			clean: "hello 🎉 world",
		},
		{
			name:  "newlines preserved",
			input: "line1\nline2\nline3",
			clean: "line1\nline2\nline3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sanitize(tt.input)
			if tt.want != "" && strings.Contains(got, tt.want) {
				t.Errorf("Sanitize(%q) = %q — still contains %q", tt.input, got, tt.want)
			}
			if tt.clean != "" && got != tt.clean {
				t.Errorf("Sanitize(%q) = %q — want %q", tt.input, got, tt.clean)
			}
		})
	}
}

func TestSanitize_BidiStripping(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "RLO attack (Trojan Source)",
			input: "// safe\u202Eniamretxe.bat",
		},
		{
			name:  "LRO attack",
			input: "\u202Dmalicious",
		},
		{
			name:  "zero width space",
			input: "normal\u200Btext",
		},
		{
			name:  "BOM in middle of string",
			input: "some\uFEFFtext",
		},
		{
			name:  "zero width joiner",
			input: "text\u200Dmore",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sanitize(tt.input)
			for _, r := range bidiControls {
				if strings.ContainsRune(got, r) {
					t.Errorf("Sanitize(%q) = %q — still contains bidi rune U+%04X", tt.input, got, r)
				}
			}
		})
	}
}

func TestSanitize_NullBytes(t *testing.T) {
	got := Sanitize("hello\x00world")
	if strings.ContainsRune(got, 0) {
		t.Errorf("Sanitize still contains null byte: %q", got)
	}
}

func TestSanitize_Truncation(t *testing.T) {
	long := strings.Repeat("a", 5000)
	got := Sanitize(long)
	if len([]rune(got)) > 4001 { // 4000 + ellipsis
		t.Errorf("Sanitize did not truncate: got %d runes", len([]rune(got)))
	}
}

func TestSanitize_SafeContent(t *testing.T) {
	inputs := []string{
		"hello world",
		"https://example.com is a link",
		"code: `func main() { fmt.Println(\"hi\") }`",
		"emoji: 🚀🎉✨",
		"numbers: 12345",
		"japanese: こんにちは",
		"arabic: مرحبا",
	}
	for _, input := range inputs {
		got := Sanitize(input)
		if got != input {
			t.Errorf("Sanitize(%q) = %q — safe content was modified", input, got)
		}
	}
}

// FuzzSanitize ensures Sanitize never panics on arbitrary input.
func FuzzSanitize(f *testing.F) {
	// Seed with known dangerous sequences.
	f.Add("\x1b[2J\x1b[H\x1b[?1049h")
	f.Add("\x1b]8;;https://evil.com\x07click me\x1b]8;;\x07")
	f.Add("\u202Egnirts desrever")
	f.Add("hello\x00world")
	f.Add("\x1bc")
	f.Add(strings.Repeat("\x1b", 100))
	f.Add(strings.Repeat("\u202E", 100))
	f.Add("normal text with mixed \x1b[31m color \x1b[0m codes")

	f.Fuzz(func(t *testing.T, s string) {
		// Must not panic.
		result := Sanitize(s)
		// Result must not contain ESC byte (0x1b).
		if strings.ContainsRune(result, '\x1b') {
			t.Errorf("Sanitize(%q) = %q — ESC byte survived sanitization", s, result)
		}
		// Result must not contain any bidi control characters.
		for _, r := range bidiControls {
			if strings.ContainsRune(result, r) {
				t.Errorf("Sanitize(%q) = %q — bidi rune U+%04X survived", s, result, r)
			}
		}
	})
}
