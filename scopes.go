package ohauth

import (
	"encoding/json"
	"regexp"
	"strings"
)

var actionRE = regexp.MustCompile(`^\w+$`)

type Scope map[string]bool

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

func (s Scope) Add(actions ...string) {
	for _, action := range actions {
		s.addOne(action)
	}
}

func (s Scope) Contains(s2 Scope) bool {
	res := true
	for k2, _ := range s2 {
		_, ok := s[k2]
		res = res && ok
		if !res {
			break
		}

	}
	return res
}

func (s Scope) Equals(s2 Scope) bool {
	return len(s) == len(s2) && s.Contains(s2)
}

func (s Scope) Values() []string {
	out := make([]string, len(s))
	i := 0
	for k, _ := range s {
		out[i] = k
		i++
	}
	return out
}

func (s Scope) String() string {
	return strings.Join(s.Values(), ",")
}

func (s Scope) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Scope) UnmarshalJSON(inp []byte) error {
	raw := ""
	if err := json.Unmarshal(inp, &raw); err != nil {
		return err
	}

	*s = ParseScope(raw)

	return nil
}
