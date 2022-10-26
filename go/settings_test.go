package hmacbcrypt

import "testing"

func Test_ParseSettings_illegalSettingsString(t *testing.T) {
	tests := []string{
		"2a", "$3b", "$2a$xx$", "$2a$10$####", "$2a$10$v.vnO5oVlX/5zJM9TTXSz.$foo$",
	}

	for _, tt := range tests {
		name := "Illegal settings string " + tt
		t.Run(name, func(t *testing.T) {
			_, err := parseSettings(tt)
			if err == nil {
				t.Errorf("Settings string '%v' was expected to be illegal", tt)
				return
			}
		})
	}
}
