package exampleop

import (
	"crypto/sha256"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/text/language"

	"github.com/zitadel/oidc/v2/example/server/storage"
	"github.com/zitadel/oidc/v2/pkg/op"
)

const (
	pathLoggedOut = "/logged-out"
)

func init() {
	storage.RegisterClients(
		storage.NativeClient("native"),
		storage.WebClient("web", "secret"),
		storage.WebClient("api", "secret"),
	)
}

type Storage interface {
	op.Storage
	authenticate
	deviceAuthenticate
}

// SetupServer creates an OIDC server with Issuer=http://localhost:<port>
//
// Use one of the pre-made clients in storage/clients.go or register a new one.
func SetupServer(issuer string, storage Storage, extraOptions ...op.Option) *mux.Router {
	// the OpenID Provider requires a 32-byte key for (token) encryption
	// be sure to create a proper crypto random key and manage it securely!
	key := sha256.Sum256([]byte("test"))

	router := mux.NewRouter()

	// for simplicity, we provide a very small default page for users who have signed out
	router.HandleFunc(pathLoggedOut, func(w http.ResponseWriter, req *http.Request) {
		_, err := w.Write([]byte("signed out successfully"))
		if err != nil {
			log.Printf("error serving logged out page: %v", err)
		}
	})

	// creation of the OpenIDProvider with the just created in-memory Storage
	provider, err := newOP(storage, issuer, key, extraOptions...)
	if err != nil {
		log.Fatal(err)
	}

	//the provider will only take care of the OpenID Protocol, so there must be some sort of UI for the login process
	//for the simplicity of the example this means a simple page with username and password field
	//be sure to provide an IssuerInterceptor with the IssuerFromRequest from the OP so the login can select / and pass it to the storage
	l := NewLogin(storage, op.AuthCallbackURL(provider), op.NewIssuerInterceptor(provider.IssuerFromRequest))

	// regardless of how many pages / steps there are in the process, the UI must be registered in the router,
	// so we will direct all calls to /login to the login UI
	router.PathPrefix("/login/").Handler(http.StripPrefix("/login", l.router))

	router.PathPrefix("/device").Subrouter()
	registerDeviceAuth(storage, router.PathPrefix("/device").Subrouter())

	// we register the http handler of the OP on the root, so that the discovery endpoint (/.well-known/openid-configuration)
	// is served on the correct path
	//
	// if your issuer ends with a path (e.g. http://localhost:9998/custom/path/),
	// then you would have to set the path prefix (/custom/path/)
	router.PathPrefix("/").Handler(provider.HttpHandler())

	return router
}

// newOP will create an OpenID Provider for localhost on a specified port with a given encryption key
// and a predefined default logout uri
// it will enable all options (see descriptions)
func newOP(storage op.Storage, issuer string, key [32]byte, extraOptions ...op.Option) (op.OpenIDProvider, error) {
	config := &op.Config{
		CryptoKey: key,

		// will be used if the end_session endpoint is called without a post_logout_redirect_uri
		DefaultLogoutRedirectURI: pathLoggedOut,

		// enables code_challenge_method S256 for PKCE (and therefore PKCE in general)
		CodeMethodS256: true,

		// enables additional client_id/client_secret authentication by form post (not only HTTP Basic Auth)
		AuthMethodPost: true,

		// enables additional authentication by using private_key_jwt
		AuthMethodPrivateKeyJWT: true,

		// enables refresh_token grant use
		GrantTypeRefreshToken: true,

		// enables use of the `request` Object parameter
		RequestObjectSupported: true,

		// this example has only static texts (in English), so we'll set the here accordingly
		SupportedUILocales: []language.Tag{language.English},

		DeviceAuthorization: op.DeviceAuthorizationConfig{
			Lifetime:     5 * time.Minute,
			PollInterval: 5 * time.Second,
			UserFormPath: "/device",
			UserCode:     op.UserCodeBase20,
		},
	}
	handler, err := op.NewOpenIDProvider(issuer, config, storage,
		append([]op.Option{
			// we must explicitly allow the use of the http issuer
			op.WithAllowInsecure(),
			// as an example on how to customize an endpoint this will change the authorization_endpoint from /authorize to /auth
			op.WithCustomAuthEndpoint(op.NewEndpoint("auth")),
		}, extraOptions...)...,
	)
	if err != nil {
		return nil, err
	}
	return handler, nil
}
