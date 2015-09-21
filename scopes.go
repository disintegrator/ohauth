package ohauth

import (
	"encoding/json"
	"regexp"
	"strings"
)

var actionRE = regexp.MustCompile(`^\w+$`)

// Scope is a set of actions defined on resources that clients may request from
// resource owners
type Scope map[string]bool

// ParseScope takes raw comma-separated string and parses into a scope object
func ParseScope(raw string) Scope {
	split := strings.Split(raw, ",")
	for i, v := range split {
		split[i] = strings.TrimSpace(v)
	}
	s := Scope{}
	s.Add(split...)
	return s
}

func (s Scope) addOne(action string) {
	if !actionRE.MatchString(action) {
		return
	}
	s[action] = true
}

// Add adds a list of actions to a scope object
func (s Scope) Add(actions ...string) {
	for _, action := range actions {
		s.addOne(action)
	}
}

// Contains determines if a scope is a subset of another
func (s Scope) Contains(s2 Scope) bool {
	res := true
	for k2 := range s2 {
		_, ok := s[k2]
		res = res && ok
		if !res {
			break
		}

	}
	return res
}

// Equals determines if two scopes are the same by comparing the actions they
// define
func (s Scope) Equals(s2 Scope) bool {
	return len(s) == len(s2) && s.Contains(s2)
}

// Values returns a list of actions held by a scope object
func (s Scope) Values() []string {
	out := make([]string, len(s))
	i := 0
	for k := range s {
		out[i] = k
		i++
	}
	return out
}

func (s Scope) String() string {
	return strings.Join(s.Values(), ",")
}

// MarshalJSON implements the json.Marshaler interface
func (s Scope) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON implements the json.Unmarshaler interface for converting JSON
// string of comma-separated scope actions and uses to populate a Scope object
func (s *Scope) UnmarshalJSON(inp []byte) error {
	raw := ""
	if err := json.Unmarshal(inp, &raw); err != nil {
		return err
	}

	*s = ParseScope(raw)

	return nil
}
