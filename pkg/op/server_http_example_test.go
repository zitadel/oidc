package op_test

import (
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// The OP is served under the issuer path /oidc. RFC 8414 locates its metadata
// at /.well-known/oauth-authorization-server/oidc, outside that prefix, so
// that URL is routed to the same handler without stripping the prefix.
func ExampleRegisterServer_authorizationServerMetadata() {
	var srv op.Server = op.UnimplementedServer{}
	endpoints := *op.DefaultEndpoints

	// The route answers only when the suffix matches the issuer's path,
	// so the issuer must be set in the request context.
	issuerFn, err := op.IssuerFromHost("/oidc")(false)
	if err != nil {
		panic(err)
	}
	h := op.RegisterServer(srv, endpoints,
		op.WithHTTPMiddleware(op.NewIssuerInterceptor(issuerFn).Handler),
	)
	mux := http.NewServeMux()
	mux.Handle("/oidc/", http.StripPrefix("/oidc", h))
	mux.Handle(oidc.AuthorizationServerMetadataEndpoint+"/oidc", h)

	_ = mux // pass to http.ListenAndServe
}
