package hmacbcrypt

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-crypt/x/bcrypt"
)

const defaultHashIdentifier = "2a"
const defaultCost = 13

type settings struct {
	Cost int
	Salt []byte
}

func (s settings) Str() string {
	return fmt.Sprintf("$%v$%v$%v", defaultHashIdentifier, s.Cost, string(bcrypt.Base64Encode(s.Salt)))
}

func parseSettings(settingsString string) (settings, error) {
	if settingsString == "" {
		return parseSettings("$2a")
	}
	settingsParts := strings.Split(settingsString, "$")
	if len(settingsParts) == 1 || settingsParts[0] != "" {
		// no $ found in settings string
		return settings{}, fmt.Errorf("settings string must start with a $ character")
	}
	if settingsParts[1] != defaultHashIdentifier {
		return settings{}, fmt.Errorf("unexpected hash identifier %v (expected: %v)", settingsParts[1], defaultHashIdentifier)
	}
	cost := defaultCost
	var salt []byte
	var err error
	if len(settingsParts) >= 3 {
		costString := settingsParts[2]
		cost, err = strconv.Atoi(costString)
		if err != nil {
			return settings{}, fmt.Errorf("could not parse cost value '%v': %v", costString, err)
		}
	}
	if len(settingsParts) == 4 && settingsParts[3] != "" {
		saltB64 := settingsParts[3]
		salt, err = bcrypt.Base64Decode([]byte(saltB64))
		if err != nil {
			return settings{}, fmt.Errorf("could not decode salt value '%v': %v", saltB64, err)
		}
	}
	if len(settingsParts) > 4 {
		return settings{}, fmt.Errorf("settings strings contains too many parts")
	}
	ret := settings{
		Cost: cost,
		Salt: salt,
	}
	if salt == nil {
		salt, err := bcrypt.NewSalt()
		if err != nil {
			return settings{}, fmt.Errorf("could not generate salt value: %v", err)
		}
		ret.Salt = salt
	}

	return ret, nil
}
