package recaptcha

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

type mockHTTPClient struct {
	resp *http.Response
	err  error
}

func (m mockHTTPClient) PostForm(string, url.Values) (*http.Response, error) {
	return m.resp, m.err
}

func TestFetchRecaptchaV3(t *testing.T) {
	testCases := []struct {
		name               string
		httpClient         HTTPClient
		expError           error
		expValid           bool
		minAcceptableScore float64
	}{
		{
			name: "All good",
			httpClient: mockHTTPClient{
				resp: &http.Response{
					Body: ioutil.NopCloser(strings.NewReader(`
						{
							"success": true,
							"hostname": "test.correct.email",
							"score": 1.0,
							"action": "test"
						}
					`)),
				},
			},
			expValid:           true,
			minAcceptableScore: 0.3,
		},
		{
			name: "Invalid JSON body (comma at the end)",
			httpClient: mockHTTPClient{
				resp: &http.Response{
					Body: ioutil.NopCloser(strings.NewReader(`
						{
							"success": true,
							"hostname": "test.correct.email",
							"score": 1.0,
							"action": "test",
						}
					`)),
				},
			},
			expError: errors.New("invalid character '}' looking for beginning of object key string"),
		},
		{
			name: "Non empty error codes",
			httpClient: mockHTTPClient{
				resp: &http.Response{
					Body: ioutil.NopCloser(strings.NewReader(`
						{
							"success": true,
							"hostname": "test.correct.email",
							"score": 0.0,
							"action": "test",
							"error_codes": [ "invalid-input-secret", "bad-request" ]
						}
					`)),
				},
			},
			expError: errors.New("invalid-input-secret, bad-request"),
		},
		{
			name: "Score too low",
			httpClient: mockHTTPClient{
				resp: &http.Response{
					Body: ioutil.NopCloser(strings.NewReader(`
						{
							"success": true,
							"hostname": "test.correct.email",
							"score": 0.2,
							"action": "test"
						}
					`)),
				},
			},
			minAcceptableScore: 0.5,
		},
		{
			name: "Http client error",
			httpClient: mockHTTPClient{
				err: errors.New("some transport error"),
			},
			expError: errors.New("some transport error"),
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			client := NewWithClient("", tt.minAcceptableScore, tt.httpClient)
			valid, err := client.FetchRecaptchaV3("", "")
			if err != nil && err.Error() != tt.expError.Error() {
				t.Errorf("\nExp error: %v\nGot error: %v", tt.expError, err)
				return
			}

			if valid != tt.expValid {
				t.Errorf("\nExp valid %t\nGot valid %t", tt.expValid, valid)
				return
			}
		})
	}
}
