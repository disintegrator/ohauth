package ohauth

import (
	"encoding/json"
	"mime"
	"net/http"
)

func JSONRequestsOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		t, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if t != "application/json" || err != nil {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			w.Write([]byte(`{"message": "Media type must be JSON"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func handleUnsupportedMethod(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusMethodNotAllowed)
	w.Header().Add("Content-Type", "application/json; charset=utf-8")
	w.Write([]byte(`{"message": "Method not allowed"}`))
}

func abortJSON(w http.ResponseWriter, status int, obj interface{}) {
	out, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	w.WriteHeader(status)
	w.Write(out)
}

func Handler(p *Provider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			handleAuthorizeGET(p, w, r)
		case "POST":
			handleAuthorizePOST(p, w, r)
		default:
			handleUnsupportedMethod(w, r)
		}
	})
	return JSONRequestsOnly(mux)
}

func handleAuthorizeGET(p *Provider, w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cid := q.Get("client_id")
	session := q.Get("session")
	state := q.Get("state")
	scope := q.Get("scope")

	client, err := p.FetchClient(cid)
	if err != nil {
		panic(err)
	}

	sc, err := p.Parse(client, session)
	if err != nil {
		panic(err)
	}

	cr := &CodeRequest{p, client, sc, ParseScope(scope), state}
	verr, err := cr.Validate()
	if err != nil {
		panic(err)
	}
	if verr != nil {
		abortJSON(w, 400, verr)
	}
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"message": "Not implemented"}`))
}

func handleAuthorizePOST(p *Provider, w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"message": "Not implemented"}`))
}
