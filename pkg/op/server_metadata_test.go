package op_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// metadataCall records what a MetadataServer method was called with.
// It is also the response body, so a test can read it back.
type metadataCall struct {
	Method     string `json:"method"`
	IssuerPath string `json:"issuer_path"`
	Tenant     string `json:"tenant"`
	Issuer     string `json:"issuer,omitempty"`
}

const (
	methodOpenID = "OpenIDConfiguration"
	methodAS     = "AuthorizationServerMetadata"
)

type recordingMetadataServer struct {
	op.UnimplementedMetadataServer
	calls []metadataCall
}

func (s *recordingMetadataServer) record(ctx context.Context, method string, r *op.Request[op.MetadataRequest]) (*op.Response, error) {
	call := metadataCall{
		Method:     method,
		IssuerPath: r.Data.IssuerPath,
		Tenant:     op.TenantFromContext(ctx),
		Issuer:     op.IssuerFromContext(ctx),
	}
	s.calls = append(s.calls, call)
	return op.NewResponse(call), nil
}

func (s *recordingMetadataServer) OpenIDConfiguration(ctx context.Context, r *op.Request[op.MetadataRequest]) (*op.Response, error) {
	return s.record(ctx, methodOpenID, r)
}

func (s *recordingMetadataServer) AuthorizationServerMetadata(ctx context.Context, r *op.Request[op.MetadataRequest]) (*op.Response, error) {
	return s.record(ctx, methodAS, r)
}

func serveMetadata(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func decodeMetadataCall(t *testing.T, rec *httptest.ResponseRecorder) metadataCall {
	t.Helper()
	var call metadataCall
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&call))
	return call
}

// assertJSONError asserts a JSON error body with the status code,
// as WriteError writes it.
func assertJSONError(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	assert.Equal(t, status, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var oidcErr oidc.Error
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&oidcErr))
	assert.Equal(t, oidc.InvalidRequest, oidcErr.ErrorType)
}

// metadataPathTest is a request path with the call it must produce,
// or a 404 when want is nil.
type metadataPathTest struct {
	name string
	path string
	want *metadataCall
}

func runMetadataPathTests(t *testing.T, server *recordingMetadataServer, h http.Handler, tests []metadataPathTest) {
	t.Helper()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server.calls = nil
			rec := serveMetadata(t, h, http.MethodGet, tt.path)
			if tt.want == nil {
				assertJSONError(t, rec, http.StatusNotFound)
				assert.Empty(t, server.calls, "server must not be called")
				return
			}
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, *tt.want, decodeMetadataCall(t, rec))
			assert.Equal(t, []metadataCall{*tt.want}, server.calls)
		})
	}
}

func TestMetadataHandler_paths(t *testing.T) {
	server := new(recordingMetadataServer)
	h := op.RegisterMetadataServer(server)

	runMetadataPathTests(t, server, h, []metadataPathTest{
		// RFC 8414 section 3
		{
			name: "AS metadata, pathless issuer",
			path: "/.well-known/oauth-authorization-server",
			want: &metadataCall{Method: methodAS},
		},
		{
			name: "AS metadata, one segment sets no tenant without the option",
			path: "/.well-known/oauth-authorization-server/p1",
			want: &metadataCall{Method: methodAS, IssuerPath: "/p1"},
		},
		{
			name: "AS metadata, multi segment",
			path: "/.well-known/oauth-authorization-server/a/b",
			want: &metadataCall{Method: methodAS, IssuerPath: "/a/b"},
		},
		// RFC 8414 section 5
		{
			name: "openid-configuration, pathless issuer",
			path: "/.well-known/openid-configuration",
			want: &metadataCall{Method: methodOpenID},
		},
		{
			name: "openid-configuration, RFC 8414 form, one segment",
			path: "/.well-known/openid-configuration/p1",
			want: &metadataCall{Method: methodOpenID, IssuerPath: "/p1"},
		},
		{
			name: "openid-configuration, RFC 8414 form, multi segment",
			path: "/.well-known/openid-configuration/a/b",
			want: &metadataCall{Method: methodOpenID, IssuerPath: "/a/b"},
		},
		// OpenID Connect Discovery section 4
		{
			name: "openid-configuration, OIDC form, one segment",
			path: "/p1/.well-known/openid-configuration",
			want: &metadataCall{Method: methodOpenID, IssuerPath: "/p1"},
		},
		{
			name: "openid-configuration, OIDC form, multi segment",
			path: "/a/b/.well-known/openid-configuration",
			want: &metadataCall{Method: methodOpenID, IssuerPath: "/a/b"},
		},
		{
			name: "ambiguous path takes the RFC 8414 form",
			path: "/.well-known/openid-configuration/.well-known/openid-configuration",
			want: &metadataCall{Method: methodOpenID, IssuerPath: "/.well-known/openid-configuration"},
		},
		// percent-encoding
		{
			name: "encoded slash is decoded once and separates segments",
			path: "/.well-known/openid-configuration/a%2Fb",
			want: &metadataCall{Method: methodOpenID, IssuerPath: "/a/b"},
		},
		{
			name: "double-encoded slash is decoded only once",
			path: "/.well-known/openid-configuration/a%252Fb",
			want: &metadataCall{Method: methodOpenID, IssuerPath: "/a%2Fb"},
		},
		{
			name: "encoded space in the OIDC form",
			path: "/p%201/.well-known/openid-configuration",
			want: &metadataCall{Method: methodOpenID, IssuerPath: "/p 1"},
		},
		// no match
		{name: "trailing slash on issuer path", path: "/.well-known/oauth-authorization-server/p1/"},
		{name: "trailing slash on pathless", path: "/.well-known/openid-configuration/"},
		{name: "empty segment", path: "/.well-known/oauth-authorization-server//p1"},
		{name: "empty segment in OIDC form", path: "/p1//.well-known/openid-configuration"},
		{name: "well-known name with suffix", path: "/.well-known/oauth-authorization-serverx"},
		{name: "OIDC form with suffix", path: "/p1/.well-known/openid-configurationx"},
		{name: "other well-known", path: "/.well-known/other"},
		{name: "root", path: "/"},
		{name: "other path", path: "/p1/authorize"},
		{name: "well-known segment alone", path: "/.well-known"},
		// dot segments never name an issuer
		{name: "dot as issuer path", path: "/.well-known/openid-configuration/."},
		{name: "dot-dot as issuer path", path: "/.well-known/oauth-authorization-server/.."},
		{name: "encoded dot-dot as issuer path", path: "/.well-known/oauth-authorization-server/%2E%2E"},
		{name: "dot in OIDC form", path: "/./.well-known/openid-configuration"},
		{name: "dot-dot inside a multi segment path", path: "/a/../b/.well-known/openid-configuration"},
	})
}

func TestMetadataHandler_tenantPrefix(t *testing.T) {
	for _, prefix := range []string{"/oauth", "/oauth/", "oauth", "oauth/"} {
		t.Run(prefix, func(t *testing.T) {
			server := new(recordingMetadataServer)
			h := op.RegisterMetadataServer(server, op.WithTenantPrefix(prefix))

			runMetadataPathTests(t, server, h, []metadataPathTest{
				{
					name: "AS metadata",
					path: "/.well-known/oauth-authorization-server/oauth/p1",
					want: &metadataCall{Method: methodAS, IssuerPath: "/oauth/p1", Tenant: "p1"},
				},
				{
					name: "openid-configuration, RFC 8414 form",
					path: "/.well-known/openid-configuration/oauth/p1",
					want: &metadataCall{Method: methodOpenID, IssuerPath: "/oauth/p1", Tenant: "p1"},
				},
				{
					name: "openid-configuration, OIDC form",
					path: "/oauth/p1/.well-known/openid-configuration",
					want: &metadataCall{Method: methodOpenID, IssuerPath: "/oauth/p1", Tenant: "p1"},
				},
				{
					name: "prefix alone is the empty tenant",
					path: "/.well-known/oauth-authorization-server/oauth",
					want: &metadataCall{Method: methodAS, IssuerPath: "/oauth"},
				},
				{
					name: "prefix alone is the empty tenant, RFC 8414 form",
					path: "/.well-known/openid-configuration/oauth",
					want: &metadataCall{Method: methodOpenID, IssuerPath: "/oauth"},
				},
				{
					name: "prefix alone is the empty tenant, OIDC form",
					path: "/oauth/.well-known/openid-configuration",
					want: &metadataCall{Method: methodOpenID, IssuerPath: "/oauth"},
				},
				{name: "segment after tenant", path: "/.well-known/oauth-authorization-server/oauth/p1/x"},
				{name: "segment after tenant, OIDC form", path: "/oauth/p1/x/.well-known/openid-configuration"},
				{name: "other prefix", path: "/.well-known/oauth-authorization-server/other/p1"},
				{name: "no tenant without prefix", path: "/.well-known/oauth-authorization-server/p1"},
				{name: "pathless issuer", path: "/.well-known/oauth-authorization-server"},
				{name: "pathless issuer, openid-configuration", path: "/.well-known/openid-configuration"},
				{name: "dot as tenant", path: "/.well-known/openid-configuration/oauth/."},
				{name: "dot-dot as tenant", path: "/.well-known/openid-configuration/oauth/.."},
				{name: "encoded dot-dot as tenant", path: "/.well-known/openid-configuration/oauth/%2E%2E"},
				{name: "dot-dot as tenant, OIDC form", path: "/oauth/../.well-known/openid-configuration"},
			})
		})
	}

	// The option set to "" is not the same as no option: only the empty
	// issuer path and single-segment ones are served, as the OP handler
	// with the same option reads "/a/b/..." as tenant "a".
	for _, prefix := range []string{"", "/"} {
		t.Run("empty prefix "+strconv.Quote(prefix), func(t *testing.T) {
			server := new(recordingMetadataServer)
			h := op.RegisterMetadataServer(server, op.WithTenantPrefix(prefix))
			runMetadataPathTests(t, server, h, []metadataPathTest{
				{
					name: "one segment",
					path: "/.well-known/oauth-authorization-server/a",
					want: &metadataCall{Method: methodAS, IssuerPath: "/a", Tenant: "a"},
				},
				{
					name: "one segment, RFC 8414 form",
					path: "/.well-known/openid-configuration/a",
					want: &metadataCall{Method: methodOpenID, IssuerPath: "/a", Tenant: "a"},
				},
				{
					name: "one segment, OIDC form",
					path: "/a/.well-known/openid-configuration",
					want: &metadataCall{Method: methodOpenID, IssuerPath: "/a", Tenant: "a"},
				},
				{
					name: "pathless issuer is the empty tenant",
					path: "/.well-known/oauth-authorization-server",
					want: &metadataCall{Method: methodAS},
				},
				{
					name: "pathless issuer, openid-configuration",
					path: "/.well-known/openid-configuration",
					want: &metadataCall{Method: methodOpenID},
				},
				{name: "multi segment", path: "/.well-known/oauth-authorization-server/a/b"},
				{name: "multi segment, RFC 8414 form", path: "/.well-known/openid-configuration/a/b"},
				{name: "multi segment, OIDC form", path: "/a/b/.well-known/openid-configuration"},
			})
		})
	}

	t.Run("no option sets no tenant and passes every issuer path through", func(t *testing.T) {
		server := new(recordingMetadataServer)
		h := op.RegisterMetadataServer(server)
		runMetadataPathTests(t, server, h, []metadataPathTest{
			{
				name: "one segment",
				path: "/.well-known/openid-configuration/a",
				want: &metadataCall{Method: methodOpenID, IssuerPath: "/a"},
			},
			{
				name: "one segment, OIDC form",
				path: "/a/.well-known/openid-configuration",
				want: &metadataCall{Method: methodOpenID, IssuerPath: "/a"},
			},
			{
				name: "RFC 8414 form",
				path: "/.well-known/openid-configuration/a/b",
				want: &metadataCall{Method: methodOpenID, IssuerPath: "/a/b"},
			},
			{
				name: "OIDC form",
				path: "/a/b/.well-known/openid-configuration",
				want: &metadataCall{Method: methodOpenID, IssuerPath: "/a/b"},
			},
		})
	})
}

// issuerFromTenant builds the issuer from the tenant on the context,
// as an IssuerInterceptor in a multi-tenant deployment would.
func issuerFromTenant(prefix string) *op.IssuerInterceptor {
	return op.NewIssuerInterceptor(func(r *http.Request) string {
		issuer := "https://op.example.com" + prefix
		if tenant := op.TenantFromContext(r.Context()); tenant != "" {
			issuer += "/" + tenant
		}
		return issuer
	})
}

func TestMetadataHandler_issuerInterceptor(t *testing.T) {
	server := new(recordingMetadataServer)
	h := op.RegisterMetadataServer(server,
		op.WithTenantPrefix("/oauth"),
		op.WithHTTPMiddleware(issuerFromTenant("/oauth").Handler),
	)

	rec := serveMetadata(t, h, http.MethodGet, "/.well-known/oauth-authorization-server/oauth/p1")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, metadataCall{
		Method:     methodAS,
		IssuerPath: "/oauth/p1",
		Tenant:     "p1",
		Issuer:     "https://op.example.com/oauth/p1",
	}, decodeMetadataCall(t, rec))
}

// recordingServer is a Server whose authorize endpoint records the tenant.
type recordingServer struct {
	op.UnimplementedServer
	tenants []string
	issuers []string
}

var errRecorded = oidc.ErrInvalidRequest().WithDescription("recorded")

func (s *recordingServer) VerifyAuthRequest(ctx context.Context, r *op.Request[oidc.AuthRequest]) (*op.ClientRequest[oidc.AuthRequest], error) {
	s.tenants = append(s.tenants, op.TenantFromContext(ctx))
	return nil, op.NewStatusError(errRecorded, http.StatusTeapot)
}

func (s *recordingServer) Health(ctx context.Context, r *op.Request[struct{}]) (*op.Response, error) {
	s.issuers = append(s.issuers, op.IssuerFromContext(ctx))
	return op.NewResponse(op.Status{Status: "ok " + op.TenantFromContext(ctx)}), nil
}

func TestMetadataHandler_serveMux(t *testing.T) {
	const prefix = "/oauth"
	issuerMW := issuerFromTenant(prefix).Handler
	metaServer := new(recordingMetadataServer)
	opServer := new(recordingServer)
	meta := op.RegisterMetadataServer(metaServer, op.WithTenantPrefix(prefix), op.WithHTTPMiddleware(issuerMW))
	opHandler := op.RegisterServer(opServer, *op.DefaultEndpoints, op.WithTenantPrefix(prefix), op.WithHTTPMiddleware(issuerMW))

	mux := http.NewServeMux()
	require.NotPanics(t, func() {
		mux.Handle("/.well-known/", meta)
		mux.Handle(prefix+"/{t}/.well-known/openid-configuration", meta)
		// The OIDC form of the platform issuer would otherwise reach the OP
		// handler's own discovery route as the empty tenant.
		mux.Handle(prefix+"/.well-known/openid-configuration", meta)
		mux.Handle(prefix+"/", opHandler)
	})

	want := metadataCall{IssuerPath: "/oauth/p1", Tenant: "p1", Issuer: "https://op.example.com/oauth/p1"}
	for path, method := range map[string]string{
		"/.well-known/oauth-authorization-server/oauth/p1": methodAS,
		"/.well-known/openid-configuration/oauth/p1":       methodOpenID,
		"/oauth/p1/.well-known/openid-configuration":       methodOpenID,
	} {
		t.Run(path, func(t *testing.T) {
			rec := serveMetadata(t, mux, http.MethodGet, path)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			want := want
			want.Method = method
			assert.Equal(t, want, decodeMetadataCall(t, rec))
		})
	}

	t.Run("authorize reaches the OP handler", func(t *testing.T) {
		rec := serveMetadata(t, mux, http.MethodGet, "/oauth/p1/authorize?client_id=x")
		assert.Equal(t, http.StatusTeapot, rec.Code, rec.Body.String())
		assert.Equal(t, []string{"p1"}, opServer.tenants)
	})
	t.Run("both handlers see the same tenant and issuer", func(t *testing.T) {
		opServer.issuers = nil
		rec := serveMetadata(t, mux, http.MethodGet, "/oauth/p1/healthz")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.JSONEq(t, `{"status":"ok p1"}`, rec.Body.String())
		assert.Equal(t, []string{want.Issuer}, opServer.issuers)
	})
	t.Run("platform issuer is the empty tenant on both handlers", func(t *testing.T) {
		const platform = "https://op.example.com/oauth"
		for path, method := range map[string]string{
			"/.well-known/oauth-authorization-server/oauth": methodAS,
			"/.well-known/openid-configuration/oauth":       methodOpenID,
			"/oauth/.well-known/openid-configuration":       methodOpenID,
		} {
			rec := serveMetadata(t, mux, http.MethodGet, path)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, metadataCall{Method: method, IssuerPath: "/oauth", Issuer: platform}, decodeMetadataCall(t, rec), path)
		}
		opServer.issuers = nil
		rec := serveMetadata(t, mux, http.MethodGet, "/oauth/healthz")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.JSONEq(t, `{"status":"ok "}`, rec.Body.String())
		assert.Equal(t, []string{platform}, opServer.issuers)
	})
	t.Run("unknown well-known is a 404", func(t *testing.T) {
		rec := serveMetadata(t, mux, http.MethodGet, "/.well-known/other")
		assertJSONError(t, rec, http.StatusNotFound)
	})
	t.Run("patterns without a static prefix conflict", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.Handle("/.well-known/", meta)
		assert.Panics(t, func() {
			mux.Handle("/{t}/.well-known/", meta)
		})
	})
}

func TestMetadataHandler_chi(t *testing.T) {
	server := new(recordingMetadataServer)
	meta := op.RegisterMetadataServer(server)

	t.Run("Handle", func(t *testing.T) {
		r := chi.NewRouter()
		r.Handle("/.well-known/*", meta)
		runMetadataPathTests(t, server, r, []metadataPathTest{
			{
				name: "AS metadata",
				path: "/.well-known/oauth-authorization-server/p1",
				want: &metadataCall{Method: methodAS, IssuerPath: "/p1"},
			},
			{
				name: "RFC 8414 form",
				path: "/.well-known/openid-configuration/a/b",
				want: &metadataCall{Method: methodOpenID, IssuerPath: "/a/b"},
			},
			{name: "other well-known", path: "/.well-known/other"},
		})
	})

	t.Run("Mount", func(t *testing.T) {
		r := chi.NewRouter()
		r.Mount("/", meta)
		runMetadataPathTests(t, server, r, []metadataPathTest{
			{
				name: "AS metadata",
				path: "/.well-known/oauth-authorization-server/p1",
				want: &metadataCall{Method: methodAS, IssuerPath: "/p1"},
			},
			{
				name: "OIDC form",
				path: "/p1/.well-known/openid-configuration",
				want: &metadataCall{Method: methodOpenID, IssuerPath: "/p1"},
			},
			{
				name: "OIDC form, encoded slash decoded once",
				path: "/a%2Fb/.well-known/openid-configuration",
				want: &metadataCall{Method: methodOpenID, IssuerPath: "/a/b"},
			},
			{name: "other path", path: "/p1/other"},
		})
	})

	// StripSlashes sets the route path from the decoded URL path, not
	// from the raw path, so the handler must not decode it again.
	t.Run("StripSlashes", func(t *testing.T) {
		for name, build := range map[string]func(h http.Handler) http.Handler{
			"Handle": func(h http.Handler) http.Handler {
				r := chi.NewRouter()
				r.Use(middleware.StripSlashes)
				r.Handle("/.well-known/*", h)
				r.Handle("/*", h)
				return r
			},
			"Mount": func(h http.Handler) http.Handler {
				r := chi.NewRouter()
				r.Use(middleware.StripSlashes)
				r.Mount("/", h)
				return r
			},
		} {
			t.Run(name, func(t *testing.T) {
				t.Run("prefix", func(t *testing.T) {
					server := new(recordingMetadataServer)
					h := build(op.RegisterMetadataServer(server, op.WithTenantPrefix("/oauth")))
					runMetadataPathTests(t, server, h, []metadataPathTest{
						{
							name: "stripped slash, decoded once",
							path: "/.well-known/openid-configuration/oauth/p%2541%2B/",
							want: &metadataCall{Method: methodOpenID, IssuerPath: "/oauth/p%41+", Tenant: "p%41+"},
						},
						{
							name: "stripped slash, OIDC form, decoded once",
							path: "/oauth/p%2541%2B/.well-known/openid-configuration/",
							want: &metadataCall{Method: methodOpenID, IssuerPath: "/oauth/p%41+", Tenant: "p%41+"},
						},
						{
							name: "no slash to strip keeps the raw route path",
							path: "/oauth/p%2B1/.well-known/openid-configuration",
							want: &metadataCall{Method: methodOpenID, IssuerPath: "/oauth/p+1", Tenant: "p+1"},
						},
						{
							name: "no slash to strip, RFC 8414 form",
							path: "/.well-known/oauth-authorization-server/oauth/p%2541",
							want: &metadataCall{Method: methodAS, IssuerPath: "/oauth/p%41", Tenant: "p%41"},
						},
					})
				})
				t.Run("no prefix", func(t *testing.T) {
					server := new(recordingMetadataServer)
					h := build(op.RegisterMetadataServer(server))
					runMetadataPathTests(t, server, h, []metadataPathTest{
						{
							name: "stripped slash, encoded slash decoded once",
							path: "/.well-known/openid-configuration/a%252Fb%2B/",
							want: &metadataCall{Method: methodOpenID, IssuerPath: "/a%2Fb+"},
						},
						{
							name: "stripped slash, OIDC form",
							path: "/a%252Fb%2B/.well-known/openid-configuration/",
							want: &metadataCall{Method: methodOpenID, IssuerPath: "/a%2Fb+"},
						},
					})
				})
			})
		}
	})
}

func TestMetadataHandler_Intercept(t *testing.T) {
	server := new(recordingMetadataServer)
	meta := op.RegisterMetadataServer(server)

	var nextPaths []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextPaths = append(nextPaths, r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	})
	h := meta.Intercept(next)

	rec := serveMetadata(t, h, http.MethodGet, "/p1/.well-known/openid-configuration")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, metadataCall{Method: methodOpenID, IssuerPath: "/p1"}, decodeMetadataCall(t, rec))
	assert.Empty(t, nextPaths)

	rec = serveMetadata(t, h, http.MethodGet, "/p1/authorize")
	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, []string{"/p1/authorize"}, nextPaths)
	assert.Len(t, server.calls, 1)
}

func TestMetadataHandler_methods(t *testing.T) {
	const path = "/.well-known/openid-configuration/p1"
	server := new(recordingMetadataServer)
	h := op.RegisterMetadataServer(server)

	t.Run("GET", func(t *testing.T) {
		server.calls = nil
		rec := serveMetadata(t, h, http.MethodGet, path)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Len(t, server.calls, 1)
	})
	t.Run("HEAD", func(t *testing.T) {
		server.calls = nil
		rec := serveMetadata(t, h, http.MethodHead, path)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Len(t, server.calls, 1)
	})
	t.Run("POST", func(t *testing.T) {
		server.calls = nil
		rec := serveMetadata(t, h, http.MethodPost, path)
		assertJSONError(t, rec, http.StatusMethodNotAllowed)
		assert.Equal(t, "GET, HEAD", rec.Header().Get("Allow"))
		assert.Empty(t, server.calls)
	})
	t.Run("unknown method", func(t *testing.T) {
		server.calls = nil
		rec := serveMetadata(t, h, "FOO", path)
		assertJSONError(t, rec, http.StatusMethodNotAllowed)
		assert.Equal(t, "GET, HEAD", rec.Header().Get("Allow"))
		assert.Empty(t, server.calls)
	})
	t.Run("unknown method on an unknown path", func(t *testing.T) {
		server.calls = nil
		rec := serveMetadata(t, h, "FOO", "/.well-known/other")
		assertJSONError(t, rec, http.StatusNotFound)
		assert.Empty(t, server.calls)
	})
	t.Run("no match with Origin gets CORS headers", func(t *testing.T) {
		server.calls = nil
		req := httptest.NewRequest(http.MethodGet, "/.well-known/other", nil)
		req.Header.Set("Origin", "https://rp.example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assertJSONError(t, rec, http.StatusNotFound)
		assert.Equal(t, "https://rp.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, server.calls)
	})
	t.Run("no match preflight", func(t *testing.T) {
		server.calls = nil
		req := httptest.NewRequest(http.MethodOptions, "/.well-known/other", nil)
		req.Header.Set("Origin", "https://rp.example.com")
		req.Header.Set("Access-Control-Request-Method", http.MethodGet)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://rp.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, server.calls)
	})
	t.Run("OPTIONS preflight", func(t *testing.T) {
		server.calls = nil
		req := httptest.NewRequest(http.MethodOptions, path, nil)
		req.Header.Set("Origin", "https://rp.example.com")
		req.Header.Set("Access-Control-Request-Method", http.MethodGet)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://rp.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), http.MethodGet)
		assert.Empty(t, server.calls)
	})
}

// routeRecorder is a middleware that records the tenant and the paths
// the OP router sees, after the tenant was stripped.
type routeRecorder struct {
	called                           bool
	tenant, path, rawPath, routePath string
}

func (rec *routeRecorder) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.called = true
		rec.tenant = op.TenantFromContext(r.Context())
		rec.path = r.URL.Path
		rec.rawPath = r.URL.RawPath
		if rctx := chi.RouteContext(r.Context()); rctx != nil {
			rec.routePath = rctx.RoutePath
		}
		next.ServeHTTP(w, r)
	})
}

// tenantServer returns an OP handler with the tenant prefix,
// whose router middleware records into rec.
func tenantServer(prefix string, rec *routeRecorder) http.Handler {
	return op.RegisterServer(new(recordingServer), *op.DefaultEndpoints,
		op.WithTenantPrefix(prefix),
		op.WithHTTPMiddleware(rec.middleware),
	)
}

// tenantCase is a request path with the tenant and paths the OP router
// must see, or a tenant 404 when notFound is set.
type tenantCase struct {
	name          string
	prefix        string
	method        string
	path          string
	notFound      bool
	wantTenant    string
	wantPath      string
	wantRaw       string
	wantRoutePath string
}

func TestRegisterServer_tenantPrefix(t *testing.T) {
	t.Run("handler", func(t *testing.T) {
		tests := []tenantCase{
			{name: "prefix and tenant", prefix: "/oauth", path: "/oauth/p1/authorize", wantTenant: "p1", wantPath: "/authorize"},
			{name: "prefix with trailing slash", prefix: "/oauth/", path: "/oauth/p1/authorize", wantTenant: "p1", wantPath: "/authorize"},
			{name: "prefix without leading slash", prefix: "oauth", path: "/oauth/p1/authorize", wantTenant: "p1", wantPath: "/authorize"},
			{name: "prefix without any slash", prefix: "oauth/", path: "/oauth/p1/authorize", wantTenant: "p1", wantPath: "/authorize"},
			{name: "tenant only", prefix: "/oauth", path: "/oauth/p1", wantTenant: "p1", wantPath: "/"},
			{name: "tenant with trailing slash", prefix: "/oauth", path: "/oauth/p1/", wantTenant: "p1", wantPath: "/"},
			{name: "no prefix", prefix: "", path: "/p1/authorize", wantTenant: "p1", wantPath: "/authorize"},
			{name: "root prefix is no prefix", prefix: "/", path: "/p1/authorize", wantTenant: "p1", wantPath: "/authorize"},
			{name: "query is kept", prefix: "/oauth", path: "/oauth/p1/authorize?client_id=x", wantTenant: "p1", wantPath: "/authorize"},
			// the empty tenant
			{name: "prefix alone is the empty tenant", prefix: "/oauth", path: "/oauth", wantPath: "/"},
			{name: "prefix with slash is the empty tenant", prefix: "/oauth", path: "/oauth/", wantPath: "/"},
			{name: "root without prefix is the empty tenant", prefix: "", path: "/", wantPath: "/"},
			// a known route wins
			{name: "authorize is a known route", prefix: "/oauth", path: "/oauth/authorize", wantPath: "/authorize"},
			{name: "keys is a known route", prefix: "/oauth", path: "/oauth/keys", wantPath: "/keys"},
			{name: "token under the prefix name is a known route", prefix: "/oauth", path: "/oauth/oauth/token", wantPath: "/oauth/token"},
			{name: "healthz is a known route", prefix: "/oauth", path: "/oauth/healthz", wantPath: "/healthz"},
			{name: "known route without prefix", prefix: "", path: "/authorize", wantPath: "/authorize"},
			{name: "tenant before a known route", prefix: "/oauth", path: "/oauth/p1/authorize", wantTenant: "p1", wantPath: "/authorize"},
			{name: "tenant before a two segment route", prefix: "/oauth", path: "/oauth/p1/oauth/token", wantTenant: "p1", wantPath: "/oauth/token"},
			{name: "tenant before keys", prefix: "/oauth", path: "/oauth/p1/keys", wantTenant: "p1", wantPath: "/keys"},
			// percent-encoding
			{name: "encoded space decoded once", prefix: "/oauth", path: "/oauth/p%201/auth%20orize", wantTenant: "p 1", wantPath: "/auth orize"},
			{name: "raw path is kept", prefix: "/oauth", path: "/oauth/p%2B1/auth%2Borize", wantTenant: "p+1", wantPath: "/auth+orize", wantRaw: "/auth%2Borize"},
			{name: "escaped tenant before a known route", prefix: "/oauth", path: "/oauth/p%2B1/authorize", wantTenant: "p+1", wantPath: "/authorize", wantRaw: "/authorize"},
			{name: "escaped route name is a tenant", prefix: "/oauth", path: "/oauth/auth%2Borize", wantTenant: "auth+orize", wantPath: "/", wantRaw: "/"},
			{name: "route in raw form is matched as chi would", prefix: "/oauth", path: "/oauth/%61uthorize", wantTenant: "authorize", wantPath: "/", wantRaw: "/"},
			{name: "double-encoded slash decoded once", prefix: "/oauth", path: "/oauth/p%252F1/authorize", wantTenant: "p%2F1", wantPath: "/authorize"},
			{name: "encoded slash inside the tenant", prefix: "/oauth", path: "/oauth/p%2F1/authorize", notFound: true},
			{name: "encoded slash as the tenant's end", prefix: "/oauth", path: "/oauth/p1%2Fauthorize", notFound: true},
			{name: "encoded slash as the prefix's end", prefix: "/oauth", path: "/oauth%2Fp1/authorize", notFound: true},
			// no tenant
			{name: "empty segment before more path", prefix: "/oauth", path: "/oauth//authorize", notFound: true},
			{name: "dot as tenant", prefix: "/oauth", path: "/oauth/./authorize", notFound: true},
			{name: "dot-dot as tenant", prefix: "/oauth", path: "/oauth/../authorize", notFound: true},
			{name: "encoded dot-dot as tenant", prefix: "/oauth", path: "/oauth/%2E%2E/authorize", notFound: true},
			{name: "dot-dot as tenant without prefix", prefix: "", path: "/../authorize", notFound: true},
			{name: "route outside the prefix", prefix: "/oauth", path: "/authorize", notFound: true},
			{name: "other prefix", prefix: "/oauth", path: "/other/authorize", notFound: true},
			{name: "wrong prefix with tenant", prefix: "/oauth", path: "/other/p1/authorize", notFound: true},
			{name: "prefix as part of a segment", prefix: "/oauth", path: "/oauthx/p1/authorize", notFound: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				inner := new(routeRecorder)
				h := tenantServer(tt.prefix, inner)
				rec := serveMetadata(t, h, http.MethodGet, tt.path)
				if tt.notFound {
					assertJSONError(t, rec, http.StatusNotFound)
					assert.False(t, inner.called, "router must not be reached")
					return
				}
				assert.True(t, inner.called, "router must be reached")
				assert.Equal(t, tt.wantTenant, inner.tenant)
				assert.Equal(t, tt.wantPath, inner.path)
				assert.Equal(t, tt.wantRaw, inner.rawPath)
				assert.Empty(t, inner.routePath)
			})
		}
	})

	t.Run("wrong method on a known route is a 405, not a tenant", func(t *testing.T) {
		inner := new(routeRecorder)
		h := tenantServer("/oauth", inner)
		rec := serveMetadata(t, h, "FOO", "/oauth/authorize")
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.True(t, inner.called)
		assert.Empty(t, inner.tenant)
		assert.Equal(t, "/authorize", inner.path)
	})

	t.Run("WithSetRouter route is known", func(t *testing.T) {
		inner := new(routeRecorder)
		h := op.RegisterServer(new(recordingServer), *op.DefaultEndpoints,
			op.WithTenantPrefix("/oauth"),
			op.WithHTTPMiddleware(inner.middleware),
			op.WithSetRouter(func(r chi.Router) {
				r.Get("/custom", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusTeapot)
				})
			}),
		)
		rec := serveMetadata(t, h, http.MethodGet, "/oauth/custom")
		assert.Equal(t, http.StatusTeapot, rec.Code)
		assert.Empty(t, inner.tenant)
		assert.Equal(t, "/custom", inner.path)

		rec = serveMetadata(t, h, http.MethodPost, "/oauth/custom")
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, "a known route with the wrong method")
		assert.Empty(t, inner.tenant)

		rec = serveMetadata(t, h, http.MethodGet, "/oauth/p1/custom")
		assert.Equal(t, http.StatusTeapot, rec.Code)
		assert.Equal(t, "p1", inner.tenant)
		assert.Equal(t, "/custom", inner.path)
	})

	t.Run("shadowing", func(t *testing.T) {
		// Tenant T loses route R when "/T"+R is a route, and its root
		// when "/T" is a route. Default endpoints: "authorize" loses
		// only its root.
		inner := new(routeRecorder)
		h := tenantServer("/oauth", inner)
		rec := serveMetadata(t, h, http.MethodGet, "/oauth/authorize/keys")
		assert.Equal(t, http.StatusNotFound, rec.Code, "UnimplementedServer.Keys")
		assert.Equal(t, "authorize", inner.tenant, "tenant named after a route keeps its other routes")
		assert.Equal(t, "/keys", inner.path)
		serveMetadata(t, h, http.MethodGet, "/oauth/authorize")
		assert.Empty(t, inner.tenant, "but loses its root to the empty tenant's route")
		assert.Equal(t, "/authorize", inner.path)

		// Endpoints "/a" and "/b/a": tenant "b" has no "/a".
		inner = new(routeRecorder)
		h = op.RegisterServer(new(recordingServer), *op.DefaultEndpoints,
			op.WithTenantPrefix("/oauth"),
			op.WithHTTPMiddleware(inner.middleware),
			op.WithSetRouter(func(r chi.Router) {
				r.Get("/a", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
				r.Get("/b/a", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusTeapot) })
			}),
		)
		serveMetadata(t, h, http.MethodGet, "/oauth/b/a")
		assert.Empty(t, inner.tenant, "/b/a is the empty tenant's route")
		assert.Equal(t, "/b/a", inner.path)
		serveMetadata(t, h, http.MethodGet, "/oauth/b/x")
		assert.Equal(t, "b", inner.tenant, "other paths of tenant b work")
		assert.Equal(t, "/x", inner.path)
		serveMetadata(t, h, http.MethodGet, "/oauth/c/a")
		assert.Equal(t, "c", inner.tenant, "tenant c keeps /a")
		assert.Equal(t, "/a", inner.path)
	})

	t.Run("path-rewriting middleware", func(t *testing.T) {
		t.Run("through WithHTTPMiddleware runs too late (documented)", func(t *testing.T) {
			inner := new(routeRecorder)
			h := op.RegisterServer(new(recordingServer), *op.DefaultEndpoints,
				op.WithTenantPrefix("/oauth"),
				op.WithHTTPMiddleware(middleware.StripSlashes, inner.middleware),
			)
			rec := serveMetadata(t, h, http.MethodGet, "/oauth/healthz/")
			assert.Equal(t, "healthz", inner.tenant, "the trailing slash hides the known route")
			assert.Equal(t, "/", inner.path)
			assert.Equal(t, http.StatusNotFound, rec.Code)
		})
		t.Run("wrapping from outside", func(t *testing.T) {
			inner := new(routeRecorder)
			h := middleware.StripSlashes(tenantServer("/oauth", inner))
			rec := serveMetadata(t, h, http.MethodGet, "/oauth/healthz/")
			assert.Empty(t, inner.tenant)
			assert.Equal(t, "/healthz", inner.path)
			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.JSONEq(t, `{"status":"ok "}`, rec.Body.String())

			rec = serveMetadata(t, h, http.MethodGet, "/oauth/p1/healthz/")
			assert.Equal(t, "p1", inner.tenant)
			assert.Equal(t, "/healthz", inner.path)
			assert.Equal(t, http.StatusOK, rec.Code)
		})
	})

	t.Run("catch-all route shadows every tenant", func(t *testing.T) {
		inner := new(routeRecorder)
		h := op.RegisterServer(new(recordingServer), *op.DefaultEndpoints,
			op.WithTenantPrefix("/oauth"),
			op.WithHTTPMiddleware(inner.middleware),
			op.WithSetRouter(func(r chi.Router) {
				r.Handle("/*", http.NotFoundHandler())
			}),
		)
		serveMetadata(t, h, http.MethodGet, "/oauth/p1/authorize")
		assert.True(t, inner.called)
		assert.Empty(t, inner.tenant, "every path is a known route")
		assert.Equal(t, "/p1/authorize", inner.path)
	})

	t.Run("does not modify the original URL", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/oauth/p1/authorize", nil)
		tenantServer("/oauth", new(routeRecorder)).ServeHTTP(httptest.NewRecorder(), req)
		assert.Equal(t, "/oauth/p1/authorize", req.URL.Path)
		assert.Empty(t, op.TenantFromContext(req.Context()))
	})

	t.Run("404 outside the prefix carries CORS headers", func(t *testing.T) {
		h := tenantServer("/oauth", new(routeRecorder))
		req := httptest.NewRequest(http.MethodGet, "/other/", nil)
		req.Header.Set("Origin", "https://rp.example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assertJSONError(t, rec, http.StatusNotFound)
		assert.Equal(t, "https://rp.example.com", rec.Header().Get("Access-Control-Allow-Origin"))

		req = httptest.NewRequest(http.MethodOptions, "/other/", nil)
		req.Header.Set("Origin", "https://rp.example.com")
		req.Header.Set("Access-Control-Request-Method", http.MethodGet)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNoContent, rec.Code, "preflight is answered before the tenant check")
		assert.Equal(t, "https://rp.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("without the option routes at the root", func(t *testing.T) {
		server := new(recordingServer)
		inner := new(routeRecorder)
		h := op.RegisterServer(server, *op.DefaultEndpoints, op.WithHTTPMiddleware(inner.middleware))

		rec := serveMetadata(t, h, http.MethodGet, "/authorize?client_id=x")
		assert.Equal(t, http.StatusTeapot, rec.Code, rec.Body.String())
		assert.Equal(t, []string{""}, server.tenants, "no tenant is set")
		assert.Equal(t, "/authorize", inner.path, "path is left as is")

		rec = serveMetadata(t, h, http.MethodGet, "/oauth/p1/authorize")
		assert.Equal(t, http.StatusNotFound, rec.Code, "no tenant handling")
		assert.Equal(t, "/oauth/p1/authorize", inner.path)
	})

	t.Run("ServeMux", func(t *testing.T) {
		inner := new(routeRecorder)
		mux := http.NewServeMux()
		mux.Handle("/oauth/", tenantServer("/oauth", inner))

		rec := serveMetadata(t, mux, http.MethodGet, "/oauth/p1/authorize")
		assert.True(t, inner.called)
		assert.Equal(t, "p1", inner.tenant)
		assert.Equal(t, "/authorize", inner.path)
		assert.Equal(t, http.StatusTeapot, rec.Code)

		rec = serveMetadata(t, mux, http.MethodGet, "/oauth/authorize")
		assert.Empty(t, inner.tenant)
		assert.Equal(t, "/authorize", inner.path)
		assert.Equal(t, http.StatusTeapot, rec.Code)

		rec = serveMetadata(t, mux, http.MethodGet, "/oauth/")
		assert.Empty(t, inner.tenant)
		assert.Equal(t, "/", inner.path)
		assert.Equal(t, http.StatusNotFound, rec.Code, "the router's 404")
	})

	t.Run("chi Handle", func(t *testing.T) {
		inner := new(routeRecorder)
		r := chi.NewRouter()
		r.Handle("/oauth/*", tenantServer("/oauth", inner))

		rec := serveMetadata(t, r, http.MethodGet, "/oauth/p%2B1/authorize")
		assert.True(t, inner.called)
		assert.Equal(t, "p+1", inner.tenant)
		assert.Equal(t, "/authorize", inner.path)
		assert.Empty(t, inner.routePath, "Handle sets no route path")
		assert.Equal(t, http.StatusTeapot, rec.Code)

		rec = serveMetadata(t, r, http.MethodGet, "/oauth/authorize")
		assert.Empty(t, inner.tenant)
		assert.Equal(t, http.StatusTeapot, rec.Code)

		rec = serveMetadata(t, r, http.MethodGet, "/oauth//authorize")
		assertJSONError(t, rec, http.StatusNotFound)
	})

	runMountCases := func(t *testing.T, use func(chi.Router), tests []tenantCase) {
		t.Helper()
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				inner := new(routeRecorder)
				r := chi.NewRouter()
				if use != nil {
					use(r)
				}
				// chi strips the mount prefix, so the handler's prefix is "".
				r.Mount("/oauth", tenantServer("", inner))
				rec := serveMetadata(t, r, http.MethodGet, tt.path)
				if tt.notFound {
					assertJSONError(t, rec, http.StatusNotFound)
					assert.False(t, inner.called, "router must not be reached")
					return
				}
				assert.True(t, inner.called, "router must be reached")
				assert.Equal(t, tt.wantTenant, inner.tenant)
				assert.Equal(t, tt.wantRoutePath, inner.routePath)
				assert.Equal(t, httptest.NewRequest(http.MethodGet, tt.path, nil).URL.Path, inner.path, "URL is left as is")
			})
		}
	}

	t.Run("chi Mount", func(t *testing.T) {
		runMountCases(t, nil, []tenantCase{
			{name: "tenant and path", path: "/oauth/p1/authorize", wantTenant: "p1", wantRoutePath: "/authorize"},
			{name: "tenant only", path: "/oauth/p1", wantTenant: "p1", wantRoutePath: "/"},
			{name: "known route is the empty tenant", path: "/oauth/authorize", wantRoutePath: "/authorize"},
			{name: "two segment known route", path: "/oauth/oauth/token", wantRoutePath: "/oauth/token"},
			{name: "mount path alone is the empty tenant", path: "/oauth", wantRoutePath: "/"},
			{name: "mount path with slash is the empty tenant", path: "/oauth/", wantRoutePath: "/"},
			{name: "encoded space decoded once", path: "/oauth/p%201/auth%20orize", wantTenant: "p 1", wantRoutePath: "/auth orize"},
			{name: "route path keeps the raw encoding", path: "/oauth/p%2B1/auth%2Borize", wantTenant: "p+1", wantRoutePath: "/auth%2Borize"},
			{name: "escaped tenant before a known route", path: "/oauth/p%2B1/authorize", wantTenant: "p+1", wantRoutePath: "/authorize"},
			{name: "double-encoded slash decoded once", path: "/oauth/p%252F1/authorize", wantTenant: "p%2F1", wantRoutePath: "/authorize"},
			{name: "encoded slash inside the tenant", path: "/oauth/p%2F1/authorize", notFound: true},
			{name: "empty segment before more path", path: "/oauth//authorize", notFound: true},
			{name: "dot as tenant", path: "/oauth/./authorize", notFound: true},
			{name: "dot-dot as tenant", path: "/oauth/../authorize", notFound: true},
			{name: "encoded dot-dot as tenant", path: "/oauth/%2E%2E/authorize", notFound: true},
		})
	})

	// StripSlashes sets the route path from the decoded URL path, not
	// from the raw path, so the tenant must not be decoded again.
	t.Run("chi Mount with StripSlashes", func(t *testing.T) {
		runMountCases(t, func(r chi.Router) { r.Use(middleware.StripSlashes) }, []tenantCase{
			{name: "stripped slash, decoded once", path: "/oauth/p%2541%2B/authorize/", wantTenant: "p%41+", wantRoutePath: "/authorize"},
			{name: "stripped slash, tenant only", path: "/oauth/p%2541%2B/", wantTenant: "p%41+", wantRoutePath: "/"},
			{name: "stripped slash, known route is the empty tenant", path: "/oauth/authorize/", wantRoutePath: "/authorize"},
			{name: "stripped slash, mount path is the empty tenant", path: "/oauth/", wantRoutePath: "/"},
			{name: "stripped slash, encoded slash decoded once", path: "/oauth/a%252Fb%2B/authorize/", wantTenant: "a%2Fb+", wantRoutePath: "/authorize"},
			{name: "no slash to strip keeps the raw route path", path: "/oauth/p%2B1/auth%2Borize", wantTenant: "p+1", wantRoutePath: "/auth%2Borize"},
			{name: "stripped slash, dot-dot as tenant", path: "/oauth/../authorize/", notFound: true},
		})
	})

	t.Run("routes", func(t *testing.T) {
		for name, build := range map[string]func(s op.Server) http.Handler{
			"ServeMux": func(s op.Server) http.Handler {
				mux := http.NewServeMux()
				mux.Handle("/oauth/", op.RegisterServer(s, *op.DefaultEndpoints, op.WithTenantPrefix("/oauth")))
				return mux
			},
			"chi Handle": func(s op.Server) http.Handler {
				r := chi.NewRouter()
				r.Handle("/oauth/*", op.RegisterServer(s, *op.DefaultEndpoints, op.WithTenantPrefix("/oauth")))
				return r
			},
			"chi Mount": func(s op.Server) http.Handler {
				r := chi.NewRouter()
				r.Mount("/oauth", op.RegisterServer(s, *op.DefaultEndpoints, op.WithTenantPrefix("")))
				return r
			},
		} {
			t.Run(name, func(t *testing.T) {
				server := new(recordingServer)
				h := build(server)

				rec := serveMetadata(t, h, http.MethodGet, "/oauth/p1/authorize?client_id=x")
				assert.Equal(t, http.StatusTeapot, rec.Code, rec.Body.String())
				rec = serveMetadata(t, h, http.MethodGet, "/oauth/authorize?client_id=x")
				assert.Equal(t, http.StatusTeapot, rec.Code, rec.Body.String())
				assert.Equal(t, []string{"p1", ""}, server.tenants)

				rec = serveMetadata(t, h, http.MethodGet, "/oauth/p2/healthz")
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				assert.JSONEq(t, `{"status":"ok p2"}`, rec.Body.String())
				rec = serveMetadata(t, h, http.MethodGet, "/oauth/healthz")
				require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				assert.JSONEq(t, `{"status":"ok "}`, rec.Body.String())
			})
		}
	})

	t.Run("RegisterLegacyServer", func(t *testing.T) {
		inner := new(routeRecorder)
		h := op.RegisterLegacyServer(
			op.NewLegacyServer(testProvider, *op.DefaultEndpoints),
			op.AuthorizeCallbackHandler(testProvider),
			op.WithTenantPrefix("/oauth"),
			op.WithHTTPMiddleware(inner.middleware),
		)

		rec := serveMetadata(t, h, http.MethodGet, "/oauth/p1/healthz")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
		assert.Equal(t, "p1", inner.tenant)
		assert.Equal(t, "/healthz", inner.path)

		rec = serveMetadata(t, h, http.MethodGet, "/oauth/healthz")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Empty(t, inner.tenant)

		// The callback route added by RegisterLegacyServer is a known route.
		serveMetadata(t, h, http.MethodGet, "/oauth/authorize/callback")
		assert.Empty(t, inner.tenant)
		assert.Equal(t, "/authorize/callback", inner.path)

		rec = serveMetadata(t, h, http.MethodGet, "/healthz")
		assertJSONError(t, rec, http.StatusNotFound)
	})
}
