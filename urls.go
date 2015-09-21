package ohauth

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// ErrNotAbsoluteURL is returned when a parsed URL is not absolute i.e. does not
// have scheme or host
var ErrNotAbsoluteURL = errors.New("absolute urls with host are required")

// StrictURL is similar to the standard net/url.URL type except that it can be
// json marshalled and unmarshalled and forces all parsed urls to https protocol
type StrictURL url.URL

// ParseURL parses a string url and coerces the scheme to https, clears the
// querystring, sets fragment to '_=_' to create a StrictURL instance. The raw
// url must be absolute (host and scheme must be set)
func ParseURL(raw string) (*StrictURL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	u.Host = strings.TrimSpace(u.Host)
	u.Scheme = "https"
	u.RawQuery = ""
	u.Fragment = "_=_"
	if u.Host == "" || !u.IsAbs() {
		return nil, ErrNotAbsoluteURL
	}
	return (*StrictURL)(u), err
}

// MustParseURL is the same as ParseURL but panic on error instead
func MustParseURL(raw string) *StrictURL {
	u, err := ParseURL(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// MarshalJSON implements the json.Marshaler interface
func (u *StrictURL) MarshalJSON() ([]byte, error) {
	c := (*url.URL)(u)
	return json.Marshal(c.String())
}

// UnmarshalJSON implements the json.Unmarshaler that correctly parses a
// StrictURL
func (u *StrictURL) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	in, err := url.Parse(s)
	if err != nil {
		return err
	}
	*u = StrictURL(*in)
	return nil
}

func (u *StrictURL) String() string {
	if u == nil {
		return ""
	}
	unbox := (*url.URL)(u)

	return unbox.String()
}

// Compare determines if two StrictURL's are the same using simple string
// comparison. If either instance is nil the result is false.
func (u *StrictURL) Compare(u2 *StrictURL) bool {
	if u == nil || u2 == nil {
		return false
	}
	s1 := u.String()
	s2 := u2.String()
	return s1 != "" && s2 != "" && s1 == s2
}

// Clone creates a new copy of the StrictURL
func (u *StrictURL) Clone() *StrictURL {
	c, err := ParseURL(u.String())
	if err != nil {
		panic(err)
	}
	return c
}

// StringWithParams returns a string representation of a StrictURL with
// the specified query parameters
func (u *StrictURL) StringWithParams(v url.Values) string {
	c := u.Clone()
	c.RawQuery = v.Encode()
	return c.String()
}

// StringWithFragment returns a string representation of a StrictURL with
// the specified fragment
func (u *StrictURL) StringWithFragment(v url.Values) string {
	c := u.Clone()
	c.Fragment = v.Encode()
	return c.String()
}
