package ohauth

import (
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

func mergeValues(vs ...url.Values) url.Values {
	out := url.Values{}
	for _, v := range vs {
		for key, val := range v {
			out[key] = val
		}
	}
	return out
}

type context struct {
	provider  *Provider
	writer    http.ResponseWriter
	request   *http.Request
	timestamp time.Time
}

func (c *context) redirect(u string) {
	http.Redirect(c.writer, c.request, u, http.StatusFound)
}

func (c *context) fail(ru *StrictURL, e *Error, state string) {
	v := mergeValues(url.Values{}, e.Values())
	v.Set("state", state)
	c.redirect(ru.StringWithParams(v))
}

func (c *context) json(s int, o interface{}) error {
	c.writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	c.writer.WriteHeader(s)
	return json.NewEncoder(c.writer).Encode(o)
}

func (c *context) abort(status int, msg string) {
	c.writer.WriteHeader(status)
	c.writer.Write([]byte(msg))
}
