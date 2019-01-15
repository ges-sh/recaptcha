package recaptcha

import "time"

// recaptchaV3Response represents response from recaptcha API
type recaptchaV3Response struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	Score       float64   `json:"score"`
	Action      string    `json:"action"`
	ErrorCodes  *[]string `json:"error_codes"`
}
