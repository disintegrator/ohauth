package ohauth

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

var ErrNotAbsoluteURL = errors.New("absolute urls with host are required")

// StrictURL is similar to the standard net/url.URL type except that it can be
// json marshalled and unmarshalled and forces all parsed urls to https protocol
type StrictURL url.URL

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

func MustParseURL(raw string) *StrictURL {
	u, err := ParseURL(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func (u *StrictURL) MarshalJSON() ([]byte, error) {
	c := (*url.URL)(u)
	return json.Marshal(c.String())
}

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

func (u *StrictURL) Unbox() *url.URL {
	return (*url.URL)(u)
}

func (u *StrictURL) String() string {
	if u == nil {
		return ""
	}
	return u.Unbox().String()
}

func (u *StrictURL) Compare(u2 *StrictURL) bool {
	if u == nil || u2 == nil {
		return false
	}
	s1 := u.String()
	s2 := u2.String()
	return s1 != "" && s2 != "" && s1 == s2
}

func (u *StrictURL) Clone() *StrictURL {
	c, err := ParseURL(u.String())
	if err != nil {
		panic(err)
	}
	return c
}

func (u *StrictURL) StringWithParams(v url.Values) string {
	c := u.Clone()
	c.RawQuery = v.Encode()
	return c.String()
}

func (u *StrictURL) StringWithFragment(v url.Values) string {
	c := u.Clone()
	c.Fragment = v.Encode()
	return c.String()
}
