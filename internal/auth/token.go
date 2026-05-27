package auth

import "net/http"

// SetAuthHeader sets the appropriate authentication header for Molly relay.
// Legacy API keys are 64 characters long (hex-encoded SHA256).
// New session tokens are 43 characters long (base64url).
func SetAuthHeader(header http.Header, token string) {
	if token == "" {
		return
	}
	if len(token) == 64 {
		header.Set("X-API-Key", token)
	} else {
		header.Set("Authorization", "Bearer "+token)
	}
}
