package recaptcha

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

var recaptchaEndpointURL = mustParseURL("https://www.google.com/recaptcha/api/siteverify")

type HTTPClient interface {
	PostForm(url string, query url.Values) (*http.Response, error)
}

type Client struct {
	secret             string
	minAcceptableScore float64
	client             HTTPClient
}

// Returns new instance of recaptcha Client
func New(secret string, score float64) Client {
	return NewWithClient(secret, score, &http.Client{})
}

// Returns new instance of recaptcha Client with custom http client
func NewWithClient(secret string, score float64, client HTTPClient) Client {
	return Client{
		secret:             secret,
		minAcceptableScore: score,
		client:             client,
	}
}

// FetchRecaptchaV3 returns whether user is valid from the perspective of Recaptcha V3 and minimum required score. For more information about token visit https://developers.google.com/recaptcha/docs/v3.
func (c Client) FetchRecaptchaV3(token, ip string) (bool, error) {
	query := url.Values{}
	query.Add("secret", c.secret)
	query.Add("response", token)
	query.Add("remoteip", ip)

	resp, err := c.client.PostForm(recaptchaEndpointURL.String(), query)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	var recaptchaV3 RecaptchaV3Response
	err = json.NewDecoder(resp.Body).Decode(&recaptchaV3)
	if err != nil {
		return false, err
	}

	if recaptchaV3.ErrorCodes != nil && len(*recaptchaV3.ErrorCodes) > 0 {
		return false, errors.New(strings.Join(*recaptchaV3.ErrorCodes, "code: "))
	}

	return recaptchaV3.Score >= c.minAcceptableScore, nil
}
