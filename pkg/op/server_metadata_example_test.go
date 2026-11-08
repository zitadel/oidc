package op_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// exampleMetadataServer serves one configuration per tenant.
// The issuer is set by an IssuerInterceptor that reads the tenant.
type exampleMetadataServer struct {
	op.UnimplementedMetadataServer
}

func (exampleMetadataServer) OpenIDConfiguration(ctx context.Context, r *op.Request[op.MetadataRequest]) (*op.Response, error) {
	return op.NewResponse(&oidc.DiscoveryConfiguration{Issuer: op.IssuerFromContext(ctx)}), nil
}

func (exampleMetadataServer) AuthorizationServerMetadata(ctx context.Context, r *op.Request[op.MetadataRequest]) (*op.Response, error) {
	return op.NewResponse(&oidc.DiscoveryConfiguration{Issuer: op.IssuerFromContext(ctx)}), nil
}

// exampleServer is a Server whose health probe shows the tenant it runs for.
type exampleServer struct {
	op.UnimplementedServer
}

func (exampleServer) Health(ctx context.Context, r *op.Request[struct{}]) (*op.Response, error) {
	return op.NewResponse(op.Status{Status: "ok for " + op.TenantFromContext(ctx)}), nil
}

func printResponses(h http.Handler, paths ...string) {
	for _, path := range paths {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		fmt.Printf("%s -> %d %s", path, rec.Code, rec.Body.String())
	}
}

// Each tenant is an issuer directly under the host, https://op.example.com/{tenant}.
// The ServeMux patterns "/.well-known/" and "/{tenant}/.well-known/" would
// conflict, so the metadata handler intercepts the well-known paths in
// front of the mux and passes everything else on.
func ExampleMetadataHandler_Intercept() {
	issuer := op.NewIssuerInterceptor(func(r *http.Request) string {
		return "https://op.example.com/" + op.TenantFromContext(r.Context())
	})
	// Both handlers take the same WithTenantPrefix: the first path
	// segment is the tenant, and no other issuer path is served.
	meta := op.RegisterMetadataServer(exampleMetadataServer{},
		op.WithTenantPrefix(""),
		op.WithHTTPMiddleware(issuer.Handler),
	)
	opHandler := op.RegisterServer(exampleServer{}, *op.DefaultEndpoints,
		op.WithTenantPrefix(""),
		op.WithHTTPMiddleware(issuer.Handler),
	)

	mux := http.NewServeMux()
	mux.Handle("/{tenant}/", opHandler)
	root := meta.Intercept(mux)

	printResponses(root,
		"/p1/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server/p1",
		"/p1/healthz",
	)
	// Output:
	// /p1/.well-known/openid-configuration -> 200 {"issuer":"https://op.example.com/p1","request_uri_parameter_supported":false}
	// /.well-known/oauth-authorization-server/p1 -> 200 {"issuer":"https://op.example.com/p1","request_uri_parameter_supported":false}
	// /p1/healthz -> 200 {"status":"ok for p1"}
}

// Each tenant is an issuer under a static prefix, https://op.example.com/oauth/{tenant}.
// With the prefix in front of the tenant, the well-known paths and the
// OP routes register side by side on a ServeMux. Both handlers take the
// same WithTenantPrefix, so they see the same tenant for the same issuer.
func ExampleRegisterMetadataServer() {
	const prefix = "/oauth"
	issuer := op.NewIssuerInterceptor(func(r *http.Request) string {
		issuer := "https://op.example.com" + prefix
		if tenant := op.TenantFromContext(r.Context()); tenant != "" {
			issuer += "/" + tenant // the empty tenant is the issuer at the prefix itself
		}
		return issuer
	})
	meta := op.RegisterMetadataServer(exampleMetadataServer{},
		op.WithTenantPrefix(prefix),
		op.WithHTTPMiddleware(issuer.Handler),
	)
	opHandler := op.RegisterServer(exampleServer{}, *op.DefaultEndpoints,
		op.WithTenantPrefix(prefix),
		op.WithHTTPMiddleware(issuer.Handler),
	)

	mux := http.NewServeMux()
	mux.Handle("/.well-known/", meta)
	mux.Handle(prefix+"/{tenant}/.well-known/openid-configuration", meta)
	// The OIDC form of the empty tenant's issuer, https://op.example.com/oauth.
	mux.Handle(prefix+"/.well-known/openid-configuration", meta)
	mux.Handle(prefix+"/", opHandler)

	printResponses(mux,
		"/.well-known/oauth-authorization-server/oauth/p1",
		"/.well-known/openid-configuration/oauth/p1",
		"/oauth/p1/.well-known/openid-configuration",
		"/oauth/p1/healthz",
		"/oauth/.well-known/openid-configuration",
		"/oauth/healthz",
		"/.well-known/oauth-authorization-server/other/p1",
	)
	// Output:
	// /.well-known/oauth-authorization-server/oauth/p1 -> 200 {"issuer":"https://op.example.com/oauth/p1","request_uri_parameter_supported":false}
	// /.well-known/openid-configuration/oauth/p1 -> 200 {"issuer":"https://op.example.com/oauth/p1","request_uri_parameter_supported":false}
	// /oauth/p1/.well-known/openid-configuration -> 200 {"issuer":"https://op.example.com/oauth/p1","request_uri_parameter_supported":false}
	// /oauth/p1/healthz -> 200 {"status":"ok for p1"}
	// /oauth/.well-known/openid-configuration -> 200 {"issuer":"https://op.example.com/oauth","request_uri_parameter_supported":false}
	// /oauth/healthz -> 200 {"status":"ok for "}
	// /.well-known/oauth-authorization-server/other/p1 -> 404 {"error":"invalid_request","error_description":"no metadata at this path"}
}
