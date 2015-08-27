package ohauth

import "time"

type Clock interface {
	Now() time.Time
}

type DefaultClock struct{}

func (d *DefaultClock) Now() time.Time { return time.Now() }
