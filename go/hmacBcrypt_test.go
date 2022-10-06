package hmacbcrypt

import (
	"regexp"
	"testing"
)

func Test_hmac_bcrypt_hash(t *testing.T) {
	type args struct {
		password string
		settings string
		pepper   string
	}
	tests := []struct {
		name      string
		args      args
		wantRegex string
		wantErr   bool
	}{
		{
			name: "Supply password only", wantRegex: "^\\$2a\\$[0-9]{2}\\$[.\\/+A-Za-z0-9]{108}$", wantErr: false,
			args: args{password: "test-pass"},
		},
		{
			name: "Supply password and cost", wantRegex: "^\\$2a\\$10\\$[.\\/+A-Za-z0-9]{108}$", wantErr: false,
			args: args{password: "test-pass", settings: "$2a$10$"},
		},
		{
			name: "Supply password and cost + salt", wantRegex: "^\\$2a\\$10\\$v\\.vnO5oVlX/5zJM9TTXSz\\.[.\\/+A-Za-z0-9]{86}$", wantErr: false,
			args: args{password: "test-pass", settings: "$2a$10$v.vnO5oVlX/5zJM9TTXSz."},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HmacBcryptHash(tt.args.password, tt.args.settings, tt.args.pepper)
			if (err != nil) != tt.wantErr {
				t.Errorf("hmac_bcrypt_hash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			match, err := regexp.Match(tt.wantRegex, []byte(got))
			if err != nil || !match {
				t.Errorf("hmac_bcrypt_hash() '%v' not in the expected format '%v'.", got, tt.wantRegex)
			}
		})
	}
}

func Test_hmac_bcrypt_verify(t *testing.T) {
	type args struct {
		password string
		expected string
		pepper   string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Supply password and cost + salt + pepper", want: true,
			args: args{password: "test-pass", pepper: "test-pepper", expected: "$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HmacBcryptVerify(tt.args.password, tt.args.expected, tt.args.pepper); got != tt.want {
				t.Errorf("hmac_bcrypt_verify() = %v, want %v", got, tt.want)
			}
		})
	}
}
