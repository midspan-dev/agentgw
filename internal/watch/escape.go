package watch

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxValue = 2048

// Escape makes s safe to print on a terminal: every rune that is not graphic
// (controls, C1, bidi and zero-width format characters, line separators)
// becomes \uXXXX or \UXXXXXXXX, and each invalid UTF-8 byte becomes \xNN.
func Escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02X`, s[i])
		case unicode.IsGraphic(r):
			b.WriteRune(r)
		case r > 0xFFFF:
			fmt.Fprintf(&b, `\U%08X`, r)
		default:
			fmt.Fprintf(&b, `\u%04X`, r)
		}
		i += n
	}
	return b.String()
}

// cut shortens values over 2 KiB, naming the full size and hash.
func cut(s string) string {
	if len(s) <= maxValue {
		return s
	}
	n := maxValue
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return fmt.Sprintf("%s… (%d bytes, sha256 %x)", s[:n], len(s), sha256.Sum256([]byte(s)))
}

// esc is the only way an untrusted value enters formatted output.
func esc(s string) string { return Escape(cut(s)) }
