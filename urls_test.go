package ohauth

import (
	"net/url"
	"testing"
)

func TestStrictURL(t *testing.T) {
	table := []struct {
		in        string
		plain     string
		wparams   string
		wfragment string
	}{
		{
			"http://example.com/abc/123/",
			"https://example.com/abc/123/#_=_",
			"https://example.com/abc/123/?ru=http%3A%2F%2Fwww.example.com%2Fcb#_=_",
			"https://example.com/abc/123/#ru=http%253A%252F%252Fwww.example.com%252Fcb",
		},
		{
			"https://example.com/abc/123?foo=bar&x=23",
			"https://example.com/abc/123#_=_",
			"https://example.com/abc/123?ru=http%3A%2F%2Fwww.example.com%2Fcb#_=_",
			"https://example.com/abc/123#ru=http%253A%252F%252Fwww.example.com%252Fcb",
		},
		{
			"http://www.example.com:8000/abc/123?foo=bar&x=23#whatever&hello=world",
			"https://www.example.com:8000/abc/123#_=_",
			"https://www.example.com:8000/abc/123?ru=http%3A%2F%2Fwww.example.com%2Fcb#_=_",
			"https://www.example.com:8000/abc/123#ru=http%253A%252F%252Fwww.example.com%252Fcb",
		},
		{
			"https://10.2.20.10/abc/123?foo=bar&x=23",
			"https://10.2.20.10/abc/123#_=_",
			"https://10.2.20.10/abc/123?ru=http%3A%2F%2Fwww.example.com%2Fcb#_=_",
			"https://10.2.20.10/abc/123#ru=http%253A%252F%252Fwww.example.com%252Fcb",
		},
		{
			"https://10.2.20.10:3000/abc/123/?foo=bar&x=23",
			"https://10.2.20.10:3000/abc/123/#_=_",
			"https://10.2.20.10:3000/abc/123/?ru=http%3A%2F%2Fwww.example.com%2Fcb#_=_",
			"https://10.2.20.10:3000/abc/123/#ru=http%253A%252F%252Fwww.example.com%252Fcb",
		},
	}

	v := url.Values{}
	v.Set("ru", "http://www.example.com/cb")

	for _, r := range table {
		u := MustParseURL(r.in)
		s := u.String()
		sp := u.StringWithParams(v)
		sf := u.StringWithFragment(v)
		if s != r.plain {
			t.Fatalf("GOT = %s - EXPECTED = %s", s, r.plain)
		}
		if sp != r.wparams {
			t.Fatalf("GOT = %s - EXPECTED = %s", sp, r.wparams)
		}
		if sf != r.wfragment {
			t.Fatalf("GOT = %s - EXPECTED = %s", sf, r.wfragment)
		}
	}
}

func TestStrictURL_AbsoluteOnly(t *testing.T) {
	table := []string{
		"example.com/abc/123/",
		"www.example.com/abc/123?foo=bar&x=23#whatever&hello=world",
		"abc/123",
		"/abc/123#_=_",
	}

	for _, r := range table {
		_, err := ParseURL(r)
		if err != ErrNotAbsoluteURL {
			t.Fatal("Did not get correct error")
		}
	}
}

func TestStrictURL_MarshalJSON(t *testing.T) {
	u := MustParseURL("http://www.example.com:8000/abc/123?foo=bar&x=23#whatever&hello=world")
	o, err := u.MarshalJSON()
	if err != nil {
		panic(err)
	}
	a := string(o)
	e := "\"https://www.example.com:8000/abc/123#_=_\""
	if a != e {
		t.Fatalf("GOT = %s - EXPECTED = %s", a, e)
	}
}

func TestStrictURL_Compare(t *testing.T) {
	v := StrictURL(url.URL{})
	empty := &v

	table := []struct {
		a   *StrictURL
		b   *StrictURL
		res bool
	}{
		{
			MustParseURL("http://example.com/abc/123/"),
			MustParseURL("http://example.com/abc/123/"),
			true,
		},
		{
			MustParseURL("http://127.0.0.1:3000/abc/123/?foo=bar#test"),
			MustParseURL("https://127.0.0.1:3000/abc/123/"),
			true,
		},
		{
			nil,
			MustParseURL("http://example.com/abc/123/"),
			false,
		},
		{
			MustParseURL("http://example.com/abc/123/"),
			nil,
			false,
		},
		{
			empty,
			empty,
			false,
		},
	}

	for _, r := range table {
		if r.a.Compare(r.b) != r.res {
			t.Fatalf("*StrictURL(%s).Compare(*StrictURL(%s)) != %t", r.a, r.b, r.res)
		}
	}
}

func TestStrictURL_Clone(t *testing.T) {
	a := MustParseURL("http://example.com/abc/123/")
	b := a.Clone()
	aa := a.StringWithParams(url.Values{"foo": {"bar"}})
	ab := b.StringWithParams(url.Values{"baz": {"qux"}})
	ea := "https://example.com/abc/123/?foo=bar#_=_"
	eb := "https://example.com/abc/123/?baz=qux#_=_"
	if aa != ea || ab != eb {
		t.Fatalf("GOT = %s AND %s - EXPECTED = %s AND %s", aa, ab, ea, eb)
	}
}
