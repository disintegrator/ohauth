package ohauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func BenchmarkAuthorize_code(b *testing.B) {
	client := NewClient("Test Client", AuthorizationCode)
	client.Scope = ParseScope("openid,email")
	client.Status = ClientActive
	client.RedirectURI = MustParseURL("http://example.com")
	err := testProvider.Store.CreateClient(client)
	if err != nil {
		panic(err)
	}
	err = testProvider.Store.StoreAuthorization(NewAuthorization(client.ID, "testuser", client.Scope))
	if err != nil {
		panic(err)
	}

	u := testProvider.URL.Clone()
	u.Path = "/oauth/authorize"
	urlstr := u.StringWithParams(url.Values{
		"redirect_uri":  {"https://example.com"},
		"response_type": {"code"},
		"client_id":     {client.ID},
		"state":         {"testingstate"},
		"scope":         {client.Scope.String()},
	})
	r, err := http.NewRequest("GET", urlstr, nil)
	r.Header.Set("Cookie", "sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGhuLnNhYXMuZGV2OjMwMDAvIiwiaWF0IjoxNDQxNjgxMTU3LCJleHAiOjE5NDE2ODExNTcsInN1YiI6InRlc3R1c2VyIn0.u4T0sa5zHZjiMZ_H6lT2J5iuCnSRjdg-L5hPx-EkTXI")

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		w := httptest.NewRecorder()
		err := handleAuthorize(&context{
			testProvider,
			w,
			r,
			time.Now(),
		})
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkAuthorize_implicit(b *testing.B) {
	client := NewClient("Test Client", Implicit)
	client.Scope = ParseScope("openid,email")
	client.Status = ClientActive
	client.RedirectURI = MustParseURL("http://example.com")
	err := testProvider.Store.CreateClient(client)
	if err != nil {
		panic(err)
	}
	err = testProvider.Store.StoreAuthorization(NewAuthorization(client.ID, "testuser", client.Scope))
	if err != nil {
		panic(err)
	}

	u := testProvider.URL.Clone()
	u.Path = "/oauth/authorize"
	urlstr := u.StringWithParams(url.Values{
		"redirect_uri":  {"https://example.com"},
		"response_type": {"token"},
		"client_id":     {client.ID},
		"state":         {"testingstate"},
		"scope":         {client.Scope.String()},
	})
	r, err := http.NewRequest("GET", urlstr, nil)
	r.Header.Set("Cookie", "sid=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGhuLnNhYXMuZGV2OjMwMDAvIiwiaWF0IjoxNDQxNjgxMTU3LCJleHAiOjE5NDE2ODExNTcsInN1YiI6InRlc3R1c2VyIn0.u4T0sa5zHZjiMZ_H6lT2J5iuCnSRjdg-L5hPx-EkTXI")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			handleAuthorize(&context{
				testProvider,
				w,
				r,
				time.Now(),
			})
		}
	})
}
