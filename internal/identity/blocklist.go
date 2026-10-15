package identity

import (
	_ "embed"
	"strings"
)

// SecLists MIT-licensed baseline, pinned in docs/CUSTODY.md. No online lookup.
//
//go:embed password-blocklist.txt
var commonPasswords string

var blockedPasswords = func() map[string]bool {
	m := make(map[string]bool)
	for _, s := range strings.Split(commonPasswords, "\n") {
		if s = strings.TrimSpace(s); s != "" {
			m[strings.ToLower(s)] = true
		}
	}
	for _, s := range []string{"correcthorsebatterystaple", "passwordpassword", "keybashkeybashkeybash", "thisisapassword", "letmeinletmeinletmein", "12345678901234567890"} {
		m[s] = true
	}
	return m
}()

func blockedPassword(value string) bool {
	if blockedPasswords[strings.ToLower(strings.TrimSpace(value))] {
		return true
	}
	runes := []rune(value)
	for period := 1; period <= 4 && period < len(runes); period++ {
		repeated := true
		for i := period; i < len(runes); i++ {
			if runes[i] != runes[i%period] {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}
	return false
}
