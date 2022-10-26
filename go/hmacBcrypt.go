// Package hmacbcrypt implemts the `hmac-bcrypt` password hashing function, a secure scheme for using the bcrypt primitive
package hmacbcrypt

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-crypt/x/bcrypt"
)

const defaultPepper = "hmac_bcrypt"

// HmacBcryptHash creates a hash using the `hmac-bcrypt` password hashing function
// settings is a string which can be empty for default settings or configure certain aspects of the algorithm. The following values are allowed:
//   "$2a" ... equivalent to the default settings
//   "$2a$<cost>" ... The integer value cost specifies the cost factor used for bcrypt. This defaults to 13
//   "$2a$<cost>$<salt>" ... If the salt to be used for hashing is specified manually, it has to be exectly 22 bcrypt-base64 encoded characers. Otherwise, a random salt will be generated
// If pepper is left empty, a default value "hmac_bcrypt" will be used
//
// Returns the hash string in the format "$2a$<cost>$<salt(len=22)><hash(len=86)>"
func HmacBcryptHash(password, settings, pepper string) (string, error) {
	parsedSettings, err := parseSettings(settings)
	if err != nil {
		return "", fmt.Errorf("Could not parse settings: %v", err)
	}
	if pepper == "" {
		pepper = defaultPepper
	}

	preHashMac := hmac.New(sha512.New, []byte(pepper))
	preHashMac.Write([]byte(password))
	preHash := base64.StdEncoding.EncodeToString(preHashMac.Sum(nil))

	midHash, err := bcrypt.GenerateFromPasswordSalt([]byte(preHash), parsedSettings.Salt, parsedSettings.Cost)
	if err != nil {
		return "", fmt.Errorf("could not calculate bcrypt hash: %v", err)
	}

	postHashMac := hmac.New(sha512.New, []byte(pepper))
	postHashMac.Write(midHash)
	postHash := base64.StdEncoding.EncodeToString(postHashMac.Sum(nil))
	//Trailing padding characters from the hash must be removed
	postHash = strings.TrimSuffix(postHash, "==")

	return fmt.Sprintf("%v%v", parsedSettings.Str(), postHash), nil
}

// HmacBcryptVerify checcks, if a hash has been generated from the specified password
// password is the password to be verified against the hash
// expected is a hash stiring as created by the HmacBcryptHash function
// If pepper is left empty, a default value "hmac_bcrypt" will be used
func HmacBcryptVerify(password, expected, pepper string) bool {
	if len(expected) < 59 { //31 (checksum) + 22 (salt) + 1 ($) + 1 (cost) + 1 ($) + 2 (2a) + 1 ($) = 59 min length
		return false
	}
	lastDollarPos := strings.LastIndex(expected, "$")
	if lastDollarPos == -1 || len(expected) < lastDollarPos+23 {
		return false
	}

	settingsStr := expected[:lastDollarPos+23]
	recalculated, err := HmacBcryptHash(password, settingsStr, pepper)
	if err != nil {
		return false
	}
	return recalculated == expected
}
