package ohauth

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

var opRE = regexp.MustCompile(`^[a-zA-Z]+(?::[a-zA-Z]+)*$`)

type Scope struct {
	sync.Mutex
	set map[string]bool
}

func (s *Scope) addOne(op string) {
	s.Lock()
	defer s.Unlock()
	if !opRE.MatchString(op) {
		return
	}
	clean := strings.Split(op, ":")
	for i := 1; i <= len(clean); i++ {
		segment := strings.Join(clean[:i], ":")
		if _, found := s.set[segment]; found {
			return
		}
	}
	s.set[op] = true
}

func ParseScope(raw string) *Scope {
	split := strings.Split(raw, ",")
	scope := &Scope{set: make(map[string]bool, len(split))}
	scope.Add(split...)
	return scope
}

func (s *Scope) Len() int {
	return len(s.set)
}

func (s *Scope) Add(ops ...string) {
	for _, scope := range ops {
		s.addOne(scope)
	}
}

func (s *Scope) Has(op string) bool {
	clean := strings.Split(op, ":")
	for i := 1; i <= len(clean); i++ {
		segment := strings.Join(clean[:i], ":")
		if _, found := s.set[segment]; found {
			return true
		}
	}
	return false
}

func (s *Scope) Contains(sub *Scope) bool {
	found := false
	for k := range sub.set {
		found = found || s.Has(k)
	}
	return found
}

func (s *Scope) MarshalJSON() ([]byte, error) {
	l := make([]string, 0, len(s.set))
	for k, v := range s.set {
		if v {
			l = append(l, string(k))
		}
	}
	return json.Marshal(strings.Join(l, ","))
}

func (s *Scope) UnmarshalJSON(raw []byte) error {
	var in string
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	tokens := strings.Split(in, ",")
	set := make(map[string]bool, len(tokens))
	*s = Scope{set: set}
	s.Add(tokens...)
	return nil
}
