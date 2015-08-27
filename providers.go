package ohauth

type Provider struct {
	Base *URL
	Store
	Clock
	Tokenizer
	Documenter
}

func NewDefaultProvider(base *URL, store Store) *Provider {
	return &Provider{
		base,
		store,
		&DefaultClock{},
		&DefaultTokenizer{},
		&DefaultDocumenter{base},
	}
}
