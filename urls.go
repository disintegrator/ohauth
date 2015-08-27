package ohauth

import (
	"encoding/json"
	"net/url"
)

// URL is similar to the standard net/url.URL type except that it can be
// json marshalled and unmarshalled and forces all parsed urls to https protocol
type URL url.URL

func ParseURL(raw string) (*URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	u.Scheme = "https"
	return (*URL)(u), err
}

func MustParseURL(raw string) *URL {
	u, err := ParseURL(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func (u *URL) MarshalJSON() ([]byte, error) {
	c := (*url.URL)(u)
	return json.Marshal(c.String())
}

func (u *URL) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if in, err := url.Parse(s); err != nil {
		return err
	} else {
		*u = URL(*in)
	}
	return nil
}

func (u *URL) Unbox() *url.URL {
	return (*url.URL)(u)
}

func (u *URL) String() string {
	if u == nil {
		return ""
	}
	return u.Unbox().String()
}

func (u1 *URL) Compare(u2 *URL) bool {
	if u1 == nil || u2 == nil {
		return false
	}
	s1, s2 := u1.String(), u2.String()
	return s1 != "" && s2 != "" && s1 == s2
}
