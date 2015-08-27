package ohauth

import (
	"fmt"
	"strings"
)

type Documenter interface {
	URIForError(ec ErrorCode) *URL
	URIForScopeOperation(op string) *URL
}

type DefaultDocumenter struct{ Base *URL }

func (d *DefaultDocumenter) urlFromBase(path string) *URL {
	out := *d.Base
	out.Path = fmt.Sprintf("%s/%s", strings.TrimRight(out.Path, "/"), path)
	return &out
}

func (d *DefaultDocumenter) URIForError(ec ErrorCode) *URL {
	return d.urlFromBase(string(ec))
}

func (d *DefaultDocumenter) URIForScopeOperation(op string) *URL {
	return d.urlFromBase(op)
}
