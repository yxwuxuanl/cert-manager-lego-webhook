package solver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/providers/dns/desec"
)

type desecTransportFunc func(*http.Request) (*http.Response, error)

func (f desecTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDesecCleanUpOmitsCreateOnlyFields(t *testing.T) {
	// Keep both DNS discovery and HTTP requests entirely offline.
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")

	const keyAuth = "test-key-authorization"
	value := fmt.Sprintf("%q", dns01.GetChallengeInfo(t.Context(), "example.com", keyAuth).Value)

	for _, tt := range []struct {
		name      string
		remaining []string
	}{
		{name: "last challenge", remaining: []string{}},
		{name: "preserve other challenges", remaining: []string{`"other-challenge"`}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var requests []string
			config := desec.NewDefaultConfig()
			config.Token = "offline-test-token"
			config.HTTPClient = &http.Client{Transport: desecTransportFunc(func(req *http.Request) (*http.Response, error) {
				request := req.Method + " " + req.URL.Path
				requests = append(requests, request)
				var body string
				switch request {
				case "GET /api/v1/domains/":
					if got := req.URL.Query().Get("owns_qname"); got != "_acme-challenge.example.com" {
						t.Errorf("unexpected responsible domain query: %q", got)
					}
					body = `[{"name":"example.com"}]`
				case "GET /api/v1/domains/example.com/rrsets/_acme-challenge/TXT/":
					records := append([]string{value}, tt.remaining...)
					data, err := json.Marshal(map[string]any{"records": records})
					if err != nil {
						return nil, err
					}
					body = string(data)
				case "PATCH /api/v1/domains/example.com/rrsets/_acme-challenge/TXT/":
					var payload map[string]json.RawMessage
					if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
						return nil, err
					}
					// deSEC rejects subname (even an empty string) in PATCH requests.
					if len(payload) != 1 || payload["records"] == nil {
						t.Errorf("cleanup must send only records, got %v", payload)
					}
					var records []string
					if err := json.Unmarshal(payload["records"], &records); err != nil {
						return nil, err
					}
					if !reflect.DeepEqual(records, tt.remaining) {
						t.Errorf("remaining records = %#v, want %#v", records, tt.remaining)
					}
					body = `{}`
				default:
					return nil, fmt.Errorf("unexpected offline request: %s", request)
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(body)),
					Request:    req,
				}, nil
			})}
			provider, err := desec.NewDNSProviderConfig(config)
			if err != nil {
				t.Fatalf("create deSEC provider: %v", err)
			}
			wrapper := &providerWrapper{provider: provider}
			if err := wrapper.CleanUp(t.Context(), "example.com", "token", keyAuth); err != nil {
				t.Fatalf("clean up challenge: %v", err)
			}
			want := []string{
				"GET /api/v1/domains/",
				"GET /api/v1/domains/example.com/rrsets/_acme-challenge/TXT/",
				"PATCH /api/v1/domains/example.com/rrsets/_acme-challenge/TXT/",
			}
			if !reflect.DeepEqual(requests, want) {
				t.Errorf("requests = %v, want %v", requests, want)
			}
		})
	}
}
