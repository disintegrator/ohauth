package ohauth

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseScope(t *testing.T) {
	table := []struct {
		in       string
		expected []string
	}{
		{
			"user_email,order_cancel,user_friends",
			[]string{"user_email", "order_cancel", "user_friends"},
		},
		{
			"user_email,user_email,order_cancel,user_friends,order_cancel",
			[]string{"user_email", "order_cancel", "user_friends"},
		},
		{
			"user_email!!,  order_cancel,00user_friends,bad-action",
			[]string{"order_cancel", "00user_friends"},
		},
		{
			"",
			[]string{},
		},
	}
	for _, r := range table {
		scope := ParseScope(r.in)
		pass := len(scope) == len(r.expected)

		for _, a := range r.expected {
			_, ok := scope[a]
			pass = pass && ok
		}
		if !pass {
			t.Fatalf("EXPECTED = %s - GOT = %s", strings.Join(r.expected, ","), scope)
		}
	}
}

func TestScopeContains(t *testing.T) {
	table := []struct {
		in1, in2 string
		expected bool
	}{
		{
			"user_email,order_cancel,user_friends,download_report",
			"order_cancel,download_report",
			true,
		},
		{
			"user_email,order_cancel,user_friends,download_report",
			"order_cancel,password,download_report",
			false,
		},
		{
			"user_email,order_cancel,user_friends,download_report",
			"",
			true,
		},
		{
			"",
			"",
			true,
		},
	}

	for _, r := range table {
		s1 := ParseScope(r.in1)
		s2 := ParseScope(r.in2)
		if res := s1.Contains(s2); res != r.expected {
			t.Fatalf("EXPECTED = %t - GOT = %t", r.expected, res)
		}
	}
}

func TestScopeEquals(t *testing.T) {
	table := []struct {
		in1, in2 string
		expected bool
	}{
		{
			"user_email,order_cancel,user_friends,download_report",
			"user_email,download_report,user_friends,order_cancel",
			true,
		},
		{
			"user_email,order_cancel,user_friends,download_report",
			"user_email,order_cancel,user_friends,download_report,password",
			false,
		},
		{
			"", "", true,
		},
	}

	for _, r := range table {
		s1 := ParseScope(r.in1)
		s2 := ParseScope(r.in2)
		if res := s1.Equals(s2); res != r.expected {
			t.Fatalf("EXPECTED = %t - GOT = %t", r.expected, res)
		}
	}
}

func TestScopeMarshalJSON(t *testing.T) {
	s := ParseScope("user_email,order_cancel,user_friends,download_report")
	j, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	out := strings.Split(strings.Trim(string(j), `"`), ",")
	pass := len(out) == len(s)
	for _, v := range out {
		_, ok := s[v]
		pass = pass && ok
	}
	if !pass {
		t.Fatalf("EXPECTED = %s - GOT = %s", s.String(), strings.Join(out, ","))
	}
}

func TestScopeUnmarshalJSON(t *testing.T) {
	target := Scope{}
	expected := []string{"user_email", "order_cancel", "user_friends", "download_report"}
	in := `"user_email,order_cancel,user_friends,download_report"`
	if err := json.Unmarshal([]byte(in), &target); err != nil {
		t.Fatal(err)
	}

	pass := len(target) == len(expected)
	for _, v := range expected {
		_, ok := target[v]
		pass = pass && ok
	}
	if !pass {
		t.Fatalf("EXPECTED = %s - GOT = %s", strings.Join(expected, ","), target.String())
	}
}
