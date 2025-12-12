package helper

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
)

// GravatarURL generates a Gravatar URL from an email address
// Returns a default avatar if email is empty
func GravatarURL(email string, size int) string {
	if size <= 0 {
		size = 80
	}

	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" {
		// Return default avatar for empty email
		return "https://www.gravatar.com/avatar/?d=mp&s=" + string(rune(size))
	}

	hash := md5.Sum([]byte(email))
	hashStr := hex.EncodeToString(hash[:])

	// d=mp is the default "mystery person" avatar
	return "https://www.gravatar.com/avatar/" + hashStr + "?d=mp&s=" + itoa(size)
}

// itoa converts int to string without importing strconv
func itoa(i int) string {
	if i == 0 {
		return "0"
	}

	var result []byte
	negative := i < 0
	if negative {
		i = -i
	}

	for i > 0 {
		result = append([]byte{byte('0' + i%10)}, result...)
		i /= 10
	}

	if negative {
		result = append([]byte{'-'}, result...)
	}

	return string(result)
}
