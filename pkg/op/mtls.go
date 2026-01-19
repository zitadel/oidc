package op

import (
	"container/list"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/go-ldap/ldap/v3"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// contextKey is a custom type for context keys to avoid collisions.
type contextKey int

const (
	// certThumbprintKey is the context key for storing the certificate thumbprint.
	certThumbprintKey contextKey = iota
	// certChainKey is the context key for storing the client certificate chain.
	certChainKey
)

// ContextWithCertThumbprint returns a new context with the certificate thumbprint stored.
// This is used to pass the thumbprint from the authentication layer to token creation.
func ContextWithCertThumbprint(ctx context.Context, thumbprint string) context.Context {
	return context.WithValue(ctx, certThumbprintKey, thumbprint)
}

// ContextWithClientCertificateChain stores the (leaf-first) certificate chain in the context.
func ContextWithClientCertificateChain(ctx context.Context, certs []*x509.Certificate) context.Context {
	if len(certs) == 0 {
		return ctx
	}
	// Copy the slice header so callers can't mutate the stored slice.
	copied := make([]*x509.Certificate, len(certs))
	copy(copied, certs)
	return context.WithValue(ctx, certChainKey, copied)
}

// ClientCertificateChainFromContext retrieves the client certificate chain from the context.
func ClientCertificateChainFromContext(ctx context.Context) []*x509.Certificate {
	if v := ctx.Value(certChainKey); v != nil {
		if certs, ok := v.([]*x509.Certificate); ok {
			return certs
		}
	}
	return nil
}

// CertThumbprintFromContext retrieves the certificate thumbprint from the context.
// Returns empty string if no thumbprint is stored.
func CertThumbprintFromContext(ctx context.Context) string {
	if v := ctx.Value(certThumbprintKey); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// SetCertThumbprintInContext extracts the certificate from the request and stores
// the thumbprint in the context if the client requires certificate-bound tokens.
// Returns the updated context (or original if no certificate binding needed).
func SetCertThumbprintInContext(ctx context.Context, r *http.Request, client Client, mtlsConfig *MTLSConfig, boundTokensSupported bool) (context.Context, error) {
	if client == nil {
		return ctx, oidc.ErrServerError().WithDescription("missing client")
	}

	// Check if client requires certificate-bound tokens
	mtlsClient, ok := client.(HasMTLSConfig)
	if !ok {
		return ctx, nil
	}
	clientConfig := mtlsClient.GetMTLSConfig()
	if clientConfig == nil || !clientConfig.TLSClientCertificateBoundAccessTokens {
		return ctx, nil
	}

	if !boundTokensSupported {
		return ctx, oidc.ErrServerError().WithDescription("certificate-bound access tokens not supported")
	}
	if client.AccessTokenType() != AccessTokenTypeJWT {
		return ctx, oidc.ErrServerError().WithDescription("certificate-bound access tokens require JWT access tokens")
	}

	// Prefer an already extracted chain (avoids double parsing in header-mode).
	certs := ClientCertificateChainFromContext(ctx)
	if len(certs) == 0 {
		var err error
		certs, err = ClientCertificateFromRequest(r, mtlsConfig)
		if err != nil || len(certs) == 0 {
			return ctx, oidc.ErrInvalidClient().WithDescription("no client certificate provided")
		}
		ctx = ContextWithClientCertificateChain(ctx, certs)
	}

	// Store thumbprint in context
	thumbprint := CalculateCertThumbprint(certs[0])
	return ContextWithCertThumbprint(ctx, thumbprint), nil
}

// MTLSConfig is the global configuration for mTLS authentication.
type MTLSConfig struct {
	// TrustStore is the pool of trusted CA certificates.
	// Used for validating client certificate chains in tls_client_auth mode.
	TrustStore *x509.CertPool

	// RequiredPolicyOIDs specifies certificate policy OIDs that must be present.
	// Empty slice skips policy OID validation.
	RequiredPolicyOIDs []asn1.ObjectIdentifier

	// RequiredEKUs specifies Extended Key Usages that must be present.
	// Empty slice skips EKU validation.
	RequiredEKUs []x509.ExtKeyUsage

	// EnableProxyHeaders MUST be explicitly set to true to enable header-based
	// certificate extraction. Default: false (disabled).
	EnableProxyHeaders bool

	// CertificateHeader is the HTTP header name for certificate forwarding.
	// Required when EnableProxyHeaders is true.
	CertificateHeader string

	// CertificateHeaderFormat specifies how the certificate is encoded.
	// Supported values: "pem-urlencoded", "pem-base64", "der-base64", "xfcc"
	// Required when EnableProxyHeaders is true.
	CertificateHeaderFormat string

	// TrustedProxyCIDRs specifies CIDR ranges of trusted proxy IPs.
	// REQUIRED when EnableProxyHeaders=true (fail-closed policy).
	TrustedProxyCIDRs []string

	// parsedCIDRs is the parsed version of TrustedProxyCIDRs (internal)
	parsedCIDRs []*net.IPNet
	cidrOnce    sync.Once
	cidrErr     error
}

// MTLSClientConfig is the client-specific mTLS configuration.
type MTLSClientConfig struct {
	// Client identifier validation (exactly one must be set)
	SubjectDN string // RFC 4514 format Distinguished Name
	SANDNS    string // Subject Alternative Name: DNS
	SANURI    string // Subject Alternative Name: URI
	SANIP     string // Subject Alternative Name: IP Address
	SANEmail  string // Subject Alternative Name: Email

	// ClientTrustStore overrides the global TrustStore for this client.
	ClientTrustStore *x509.CertPool

	// RequiredPolicyOIDs specifies additional policy OIDs required for this client.
	RequiredPolicyOIDs []asn1.ObjectIdentifier

	// RequiredEKUs specifies additional EKUs required for this client.
	RequiredEKUs []x509.ExtKeyUsage

	// TLSClientCertificateBoundAccessTokens indicates whether this client
	// requests certificate-bound access tokens (RFC 8705 Section 3.4).
	TLSClientCertificateBoundAccessTokens bool
}

// Confirmation represents the RFC 8705 cnf claim for certificate-bound tokens.
type Confirmation struct {
	X5tS256 string `json:"x5t#S256,omitempty"`
}

// CertificateBoundClaims is a minimal helper structure for attaching cnf to token/introspection claims.
// The final token claim structs live in pkg/oidc, but this type is useful for internal plumbing/tests.
type CertificateBoundClaims struct {
	Confirmation *Confirmation `json:"cnf,omitempty"`
}

// HasMTLSConfig is an optional interface for clients that support PKI-based mTLS authentication (tls_client_auth).
type HasMTLSConfig interface {
	GetMTLSConfig() *MTLSClientConfig
}

// HasSelfSignedCertificate is an optional interface for clients that support self-signed certificate
// authentication (self_signed_tls_client_auth).
type HasSelfSignedCertificate interface {
	// GetRegisteredCertificates returns the pre-registered certificates in PEM format.
	GetRegisteredCertificates() []string
}

func (c *MTLSConfig) ensureParsedCIDRs() error {
	if c == nil {
		return nil
	}
	c.cidrOnce.Do(func() {
		if !c.EnableProxyHeaders {
			return
		}
		c.parsedCIDRs = make([]*net.IPNet, 0, len(c.TrustedProxyCIDRs))
		for _, cidr := range c.TrustedProxyCIDRs {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				c.cidrErr = fmt.Errorf("invalid CIDR %q: %w", cidr, err)
				return
			}
			c.parsedCIDRs = append(c.parsedCIDRs, ipNet)
		}
	})
	return c.cidrErr
}

// ValidateMTLSConfig validates the MTLSConfig at startup.
func ValidateMTLSConfig(config *MTLSConfig) error {
	if config == nil {
		return nil
	}

	if config.EnableProxyHeaders {
		if len(config.TrustedProxyCIDRs) == 0 {
			return errors.New("TrustedProxyCIDRs is required when EnableProxyHeaders is true")
		}
		if config.CertificateHeader == "" {
			return errors.New("CertificateHeader is required when EnableProxyHeaders is true")
		}
		if config.CertificateHeaderFormat == "" {
			return errors.New("CertificateHeaderFormat is required when EnableProxyHeaders is true")
		}
		switch config.CertificateHeaderFormat {
		case "pem-urlencoded", "pem-base64", "der-base64", "xfcc":
		default:
			return fmt.Errorf("unsupported CertificateHeaderFormat %q", config.CertificateHeaderFormat)
		}

		if err := config.ensureParsedCIDRs(); err != nil {
			return err
		}
	}

	return nil
}

// ClientCertificateFromRequest extracts the client certificate chain from the request.
func ClientCertificateFromRequest(r *http.Request, config *MTLSConfig) ([]*x509.Certificate, error) {
	if r == nil {
		return nil, errors.New("nil request")
	}
	if config == nil {
		config = &MTLSConfig{}
	}

	if config.EnableProxyHeaders {
		if len(config.TrustedProxyCIDRs) == 0 {
			return nil, errors.New("TrustedProxyCIDRs is required when EnableProxyHeaders is true")
		}
		if config.CertificateHeader == "" {
			return nil, errors.New("CertificateHeader is required when EnableProxyHeaders is true")
		}
		if config.CertificateHeaderFormat == "" {
			return nil, errors.New("CertificateHeaderFormat is required when EnableProxyHeaders is true")
		}
		if err := config.ensureParsedCIDRs(); err != nil {
			return nil, err
		}

		// Extract remote IP
		remoteHost, err := remoteHostFromAddr(r.RemoteAddr)
		if err != nil {
			return nil, errors.New("invalid remote address")
		}

		if !isFromTrustedProxy(remoteHost, config) {
			return nil, errors.New("request not from trusted proxy")
		}

		// Extract from header
		headerValue := r.Header.Get(config.CertificateHeader)
		if headerValue == "" {
			return nil, errors.New("certificate header is empty")
		}

		return parseCertificateFromHeader(headerValue, config.CertificateHeaderFormat)
	}

	// Direct TLS connection
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("no client certificate provided")
	}

	return r.TLS.PeerCertificates, nil
}

func remoteHostFromAddr(remoteAddr string) (string, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return strings.Trim(host, "[]"), nil
	}
	trimmed := strings.Trim(remoteAddr, "[]")
	if trimmed == "" {
		return "", errors.New("empty")
	}
	return trimmed, nil
}

func isFromTrustedProxy(remoteHost string, config *MTLSConfig) bool {
	if config == nil {
		return false
	}

	if err := config.ensureParsedCIDRs(); err != nil {
		return false
	}

	ip := net.ParseIP(remoteHost)
	if ip == nil {
		return false
	}

	for _, ipNet := range config.parsedCIDRs {
		if ipNet.Contains(ip) {
			return true
		}
	}

	return false
}

func parseCertificateFromHeader(headerValue, format string) ([]*x509.Certificate, error) {
	var pemData []byte

	switch format {
	case "pem-urlencoded":
		decoded, err := url.QueryUnescape(headerValue)
		if err != nil {
			return nil, fmt.Errorf("failed to URL-decode certificate: %w", err)
		}
		pemData = []byte(decoded)

	case "pem-base64":
		decoded, err := decodeBase64(headerValue)
		if err != nil {
			return nil, fmt.Errorf("failed to base64-decode certificate: %w", err)
		}
		pemData = decoded

	case "der-base64":
		decoded, err := decodeBase64(headerValue)
		if err != nil {
			return nil, fmt.Errorf("failed to base64-decode DER certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(decoded)
		if err != nil {
			return nil, fmt.Errorf("failed to parse DER certificate: %w", err)
		}
		return []*x509.Certificate{cert}, nil

	case "xfcc":
		return parseXFCCHeader(headerValue)

	default:
		return nil, fmt.Errorf("unsupported certificate header format: %s", format)
	}

	// Parse PEM certificates
	return parsePEMCertificates(pemData)
}

func decodeBase64(s string) ([]byte, error) {
	// Accept common variants used by proxies/gateways.
	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	var lastErr error
	for _, enc := range encodings {
		b, err := enc.DecodeString(s)
		if err == nil {
			return b, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func parsePEMCertificates(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		pemData = rest
	}

	if len(certs) == 0 {
		return nil, errors.New("no valid certificates found in PEM data")
	}

	return certs, nil
}

func parseXFCCHeader(headerValue string) ([]*x509.Certificate, error) {
	// Parse Envoy X-Forwarded-Client-Cert format
	// Format: Cert="...";Chain="...";...
	var certs []*x509.Certificate

	// https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/headers#x-forwarded-client-cert
	// Envoy may sanitize/append/forward XFCC; to avoid ambiguity and potential header injection in
	// multi-proxy setups, require a single XFCC element (fail-closed).
	elements := splitXFCCElements(headerValue)
	if len(elements) != 1 {
		return nil, errors.New("multiple XFCC elements are not supported; configure the proxy to sanitize XFCC")
	}

	parts := splitXFCCPairs(elements[0])
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			return nil, errors.New("invalid XFCC key-value pair")
		}
		key := strings.TrimSpace(part[:eq])
		value := strings.TrimSpace(part[eq+1:])
		value = unquoteXFCCValue(value)

		switch strings.ToLower(key) {
		case "cert":
			decoded, err := url.QueryUnescape(value)
			if err != nil {
				return nil, fmt.Errorf("failed to decode XFCC Cert: %w", err)
			}
			parsed, err := parsePEMCertificates([]byte(decoded))
			if err != nil {
				return nil, err
			}
			certs = append(certs, parsed...)
		case "chain":
			decoded, err := url.QueryUnescape(value)
			if err != nil {
				return nil, fmt.Errorf("failed to decode XFCC Chain: %w", err)
			}
			parsed, err := parsePEMCertificates([]byte(decoded))
			if err != nil {
				return nil, err
			}
			certs = append(certs, parsed...)
		}
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificates found in XFCC header")
	}

	return certs, nil
}

func splitXFCCElements(s string) []string {
	return splitXFCC(s, ',')
}

func splitXFCCPairs(s string) []string {
	return splitXFCC(s, ';')
}

func splitXFCC(s string, delim byte) []string {
	var parts []string
	var b strings.Builder
	inQuotes := false
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			b.WriteByte(c)
			continue
		}
		if inQuotes && c == '\\' {
			escaped = true
			b.WriteByte(c)
			continue
		}
		if c == '"' {
			inQuotes = !inQuotes
			b.WriteByte(c)
			continue
		}
		if !inQuotes && c == delim {
			part := strings.TrimSpace(b.String())
			if part != "" {
				parts = append(parts, part)
			}
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	last := strings.TrimSpace(b.String())
	if last != "" {
		parts = append(parts, last)
	}
	return parts
}

func unquoteXFCCValue(v string) string {
	if len(v) >= 2 && strings.HasPrefix(v, "\"") && strings.HasSuffix(v, "\"") {
		v = v[1 : len(v)-1]
		v = strings.ReplaceAll(v, `\"`, `"`)
		v = strings.ReplaceAll(v, `\\`, `\`)
	}
	return v
}

// ValidateCertificateChain validates the certificate chain against the trust store.
func ValidateCertificateChain(certs []*x509.Certificate, globalConfig *MTLSConfig, clientConfig *MTLSClientConfig) error {
	if len(certs) == 0 {
		return errors.New("no certificates provided")
	}

	leaf := certs[0]

	// Determine trust store
	var trustStore *x509.CertPool
	if globalConfig != nil {
		trustStore = globalConfig.TrustStore
	}
	if clientConfig != nil && clientConfig.ClientTrustStore != nil {
		trustStore = clientConfig.ClientTrustStore
	}

	if trustStore == nil {
		return errors.New("no trust store configured")
	}

	// Build intermediate pool from remaining certs
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         trustStore,
		Intermediates: intermediates,
		// EKU enforcement is handled separately (ValidateExtKeyUsage) based on configuration.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err := leaf.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	return nil
}

// ValidatePolicyOIDs validates that the certificate contains the required policy OIDs.
func ValidatePolicyOIDs(cert *x509.Certificate, requiredOIDs []asn1.ObjectIdentifier) error {
	if cert == nil {
		return errors.New("nil certificate")
	}
	if len(requiredOIDs) == 0 {
		return nil
	}

	for _, required := range requiredOIDs {
		found := false
		for _, policy := range cert.PolicyIdentifiers {
			if policy.Equal(required) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("certificate missing required policy OID: %s", required.String())
		}
	}

	return nil
}

// ValidateExtKeyUsage validates that the certificate contains the required EKUs.
func ValidateExtKeyUsage(cert *x509.Certificate, requiredEKUs []x509.ExtKeyUsage) error {
	if cert == nil {
		return errors.New("nil certificate")
	}
	if len(requiredEKUs) == 0 {
		return nil
	}

	for _, required := range requiredEKUs {
		found := false
		for _, eku := range cert.ExtKeyUsage {
			if eku == required {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("certificate missing required EKU: %v", required)
		}
	}

	return nil
}

// ValidateClientIdentifier validates the certificate against the client's identifier configuration.
func ValidateClientIdentifier(cert *x509.Certificate, clientConfig *MTLSClientConfig) error {
	if cert == nil {
		return errors.New("nil certificate")
	}
	if clientConfig == nil {
		return errors.New("no client configuration provided")
	}

	if err := ValidateMTLSClientConfig(clientConfig); err != nil {
		return err
	}

	if clientConfig.SubjectDN != "" {
		return matchSubjectDN(cert, clientConfig.SubjectDN)
	}
	if clientConfig.SANDNS != "" {
		return matchSANDNS(cert, clientConfig.SANDNS)
	}
	if clientConfig.SANURI != "" {
		return matchSANURI(cert, clientConfig.SANURI)
	}
	if clientConfig.SANIP != "" {
		return matchSANIP(cert, clientConfig.SANIP)
	}
	if clientConfig.SANEmail != "" {
		return matchSANEmail(cert, clientConfig.SANEmail)
	}

	return errors.New("no client identifier configured")
}

// ValidateMTLSClientConfig ensures exactly one identifier is configured (RFC 8705 requirement).
func ValidateMTLSClientConfig(clientConfig *MTLSClientConfig) error {
	if clientConfig == nil {
		return errors.New("no client configuration provided")
	}
	count := 0
	if clientConfig.SubjectDN != "" {
		count++
	}
	if clientConfig.SANDNS != "" {
		count++
	}
	if clientConfig.SANURI != "" {
		count++
	}
	if clientConfig.SANIP != "" {
		count++
	}
	if clientConfig.SANEmail != "" {
		count++
	}
	if count == 0 {
		return errors.New("no client identifier configured")
	}
	if count > 1 {
		return errors.New("multiple client identifiers configured")
	}
	return nil
}

// matchSubjectDN compares certificate Subject DN with expected DN (RFC 4514 format).
// RFC 4514 format is "CN=...,O=...,C=..." (most specific first)
// DER/ToRDNSequence order is "C,O,CN" (least specific first)
// We reverse the parsed DN to match DER order for comparison.
func matchSubjectDN(cert *x509.Certificate, expectedDN string) error {
	expectedRDNs, err := getCachedExpectedDN(expectedDN)
	if err != nil {
		return fmt.Errorf("invalid expected DN: %w", err)
	}

	// Get certificate subject as RDN sequence (DER order)
	certRDNs := cert.Subject.ToRDNSequence()

	// Compare RDN sequences
	if !rdnSequenceEqual(certRDNs, expectedRDNs) {
		return errors.New("certificate subject does not match expected DN")
	}

	return nil
}

func reverseExpectedRDNs(rdns [][]expectedAttribute) {
	for i, j := 0, len(rdns)-1; i < j; i, j = i+1, j-1 {
		rdns[i], rdns[j] = rdns[j], rdns[i]
	}
}

type expectedAttribute struct {
	TypeOID asn1.ObjectIdentifier
	Value   string
}

type cachedExpectedDN struct {
	rdns [][]expectedAttribute
	err  error
}

type lruEntry[K comparable, V any] struct {
	key   K
	value V
}

// lruCache is a small bounded LRU cache for avoiding repeated parsing in hot paths.
// It is safe for concurrent use.
type lruCache[K comparable, V any] struct {
	mu       sync.Mutex
	capacity int
	ll       *list.List
	m        map[K]*list.Element
}

func newLRU[K comparable, V any](capacity int) *lruCache[K, V] {
	if capacity < 1 {
		capacity = 1
	}
	return &lruCache[K, V]{
		capacity: capacity,
		ll:       list.New(),
		m:        make(map[K]*list.Element, capacity),
	}
}

func (c *lruCache[K, V]) Get(key K) (V, bool) {
	var zero V
	if c == nil {
		return zero, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if ele, ok := c.m[key]; ok {
		c.ll.MoveToFront(ele)
		return ele.Value.(lruEntry[K, V]).value, true
	}
	return zero, false
}

func (c *lruCache[K, V]) Add(key K, value V) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if ele, ok := c.m[key]; ok {
		ele.Value = lruEntry[K, V]{key: key, value: value}
		c.ll.MoveToFront(ele)
		return
	}

	ele := c.ll.PushFront(lruEntry[K, V]{key: key, value: value})
	c.m[key] = ele
	if c.ll.Len() > c.capacity {
		c.removeOldest()
	}
}

func (c *lruCache[K, V]) removeOldest() {
	ele := c.ll.Back()
	if ele == nil {
		return
	}
	c.ll.Remove(ele)
	ent := ele.Value.(lruEntry[K, V])
	delete(c.m, ent.key)
}

var expectedDNCache = newLRU[string, cachedExpectedDN](1024)

func getCachedExpectedDN(expectedDN string) ([][]expectedAttribute, error) {
	if expectedDN == "" {
		return nil, errors.New("empty DN")
	}
	if v, ok := expectedDNCache.Get(expectedDN); ok {
		return v.rdns, v.err
	}
	rdns, err := parseExpectedDN(expectedDN)
	if err == nil {
		// Reverse to match DER order (C, O, CN). Reverse in-place before caching.
		reverseExpectedRDNs(rdns)
	}
	expectedDNCache.Add(expectedDN, cachedExpectedDN{rdns: rdns, err: err})
	return rdns, err
}

var shortNameToOID = map[string]asn1.ObjectIdentifier{
	"CN":           {2, 5, 4, 3},
	"O":            {2, 5, 4, 10},
	"OU":           {2, 5, 4, 11},
	"C":            {2, 5, 4, 6},
	"ST":           {2, 5, 4, 8},
	"L":            {2, 5, 4, 7},
	"STREET":       {2, 5, 4, 9},
	"SERIALNUMBER": {2, 5, 4, 5},
}

func parseExpectedDN(expectedDN string) ([][]expectedAttribute, error) {
	parsed, err := ldap.ParseDN(expectedDN)
	if err != nil {
		return nil, err
	}

	rdns := make([][]expectedAttribute, 0, len(parsed.RDNs))
	for _, rdn := range parsed.RDNs {
		attrs := make([]expectedAttribute, 0, len(rdn.Attributes))
		for _, attr := range rdn.Attributes {
			oid, err := attrTypeToOID(attr.Type)
			if err != nil {
				return nil, err
			}
			attrs = append(attrs, expectedAttribute{
				TypeOID: oid,
				Value:   attr.Value,
			})
		}
		rdns = append(rdns, attrs)
	}
	return rdns, nil
}

func attrTypeToOID(expectedType string) (asn1.ObjectIdentifier, error) {
	if oid, ok := shortNameToOID[strings.ToUpper(expectedType)]; ok {
		return oid, nil
	}
	oid, err := parseOIDString(expectedType)
	if err != nil {
		return nil, fmt.Errorf("unsupported attribute type %q", expectedType)
	}
	return oid, nil
}

func parseOIDString(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, errors.New("not an OID")
	}
	oid := make(asn1.ObjectIdentifier, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			return nil, errors.New("invalid OID")
		}
		var n int
		for _, r := range p {
			if r < '0' || r > '9' {
				return nil, errors.New("invalid OID")
			}
			n = n*10 + int(r-'0')
		}
		oid = append(oid, n)
	}
	return oid, nil
}

func rdnSequenceEqual(certRDNs pkix.RDNSequence, expectedRDNs [][]expectedAttribute) bool {
	if len(certRDNs) != len(expectedRDNs) {
		return false
	}

	for i := range certRDNs {
		if !rdnEqual(certRDNs[i], expectedRDNs[i]) {
			return false
		}
	}

	return true
}

func rdnEqual(certRDN pkix.RelativeDistinguishedNameSET, expectedRDN []expectedAttribute) bool {
	if len(certRDN) != len(expectedRDN) {
		return false
	}

	matched := make([]bool, len(expectedRDN))
	for _, certAttr := range certRDN {
		found := false
		for i, expAttr := range expectedRDN {
			if matched[i] {
				continue
			}
			if certAttr.Type.Equal(expAttr.TypeOID) &&
				attrValueEqual(certAttr.Value, expAttr.Value) {
				matched[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func attrValueEqual(certValue, expectedValue any) bool {
	certStr := normalizeForMatch(fmt.Sprintf("%v", certValue))
	expStr := normalizeForMatch(fmt.Sprintf("%v", expectedValue))
	return strings.EqualFold(certStr, expStr)
}

func normalizeForMatch(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// matchSANDNS checks if the certificate contains the expected DNS SAN.
func matchSANDNS(cert *x509.Certificate, expected string) error {
	for _, dns := range cert.DNSNames {
		if strings.EqualFold(dns, expected) {
			return nil
		}
	}
	return errors.New("certificate does not contain expected DNS SAN")
}

// matchSANURI checks if the certificate contains the expected URI SAN.
func matchSANURI(cert *x509.Certificate, expected string) error {
	expectedURL, err := url.Parse(expected)
	if err != nil {
		return fmt.Errorf("invalid expected URI: %w", err)
	}

	for _, u := range cert.URIs {
		if uriEqual(u, expectedURL) {
			return nil
		}
	}
	return errors.New("certificate does not contain expected URI SAN")
}

func uriEqual(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Host, b.Host) &&
		a.Path == b.Path &&
		a.RawQuery == b.RawQuery &&
		a.Fragment == b.Fragment
}

// matchSANIP checks if the certificate contains the expected IP SAN.
func matchSANIP(cert *x509.Certificate, expected string) error {
	expectedIP := net.ParseIP(expected)
	if expectedIP == nil {
		return fmt.Errorf("invalid expected IP: %s", expected)
	}

	for _, ip := range cert.IPAddresses {
		if ip.Equal(expectedIP) {
			return nil
		}
	}
	return errors.New("certificate does not contain expected IP SAN")
}

// matchSANEmail checks if the certificate contains the expected email SAN.
func matchSANEmail(cert *x509.Certificate, expected string) error {
	expParts := strings.SplitN(expected, "@", 2)
	if len(expParts) != 2 {
		return fmt.Errorf("invalid expected email: %s", expected)
	}

	for _, email := range cert.EmailAddresses {
		certParts := strings.SplitN(email, "@", 2)
		if len(certParts) != 2 {
			continue
		}
		// Local-part: exact match (case-sensitive per RFC 5321)
		// Domain: case-insensitive
		if certParts[0] == expParts[0] &&
			strings.EqualFold(certParts[1], expParts[1]) {
			return nil
		}
	}
	return errors.New("certificate does not contain expected email SAN")
}

// ValidateTLSClientAuth performs full tls_client_auth validation (RFC 8705 Section 2.1).
// It validates:
// - certificate chain against the trust store (global or client-specific)
// - policy OIDs (global + client-specific, AND)
// - EKUs (global + client-specific, AND)
// - client identifier (Subject DN or SAN)
func ValidateTLSClientAuth(certs []*x509.Certificate, globalConfig *MTLSConfig, clientConfig *MTLSClientConfig) error {
	if len(certs) == 0 {
		return errors.New("no client certificate provided")
	}
	if clientConfig == nil {
		return errors.New("no client configuration provided")
	}
	leaf := certs[0]

	// 1. Validate certificate chain
	if err := ValidateCertificateChain(certs, globalConfig, clientConfig); err != nil {
		return fmt.Errorf("certificate chain validation failed: %w", err)
	}

	// 2. Validate global policy OIDs
	if globalConfig != nil {
		if err := ValidatePolicyOIDs(leaf, globalConfig.RequiredPolicyOIDs); err != nil {
			return fmt.Errorf("global policy OID validation failed: %w", err)
		}
		if err := ValidateExtKeyUsage(leaf, globalConfig.RequiredEKUs); err != nil {
			return fmt.Errorf("global EKU validation failed: %w", err)
		}
	}

	// 3. Validate client-specific policy OIDs and EKUs
	if len(clientConfig.RequiredPolicyOIDs) > 0 {
		if err := ValidatePolicyOIDs(leaf, clientConfig.RequiredPolicyOIDs); err != nil {
			return fmt.Errorf("client policy OID validation failed: %w", err)
		}
	}
	if len(clientConfig.RequiredEKUs) > 0 {
		if err := ValidateExtKeyUsage(leaf, clientConfig.RequiredEKUs); err != nil {
			return fmt.Errorf("client EKU validation failed: %w", err)
		}
	}
	// 4. Validate client identifier
	if err := ValidateClientIdentifier(leaf, clientConfig); err != nil {
		return err
	}

	return nil
}

type mtlsClientAuthSupport interface {
	MTLSConfig() *MTLSConfig
	AuthMethodTLSClientAuthSupported() bool
	AuthMethodSelfSignedTLSClientAuthSupported() bool
}

// validateMTLSClientAuthForClient validates an already identified mTLS client against the request certificate.
// It returns a context that contains the extracted certificate chain to avoid re-parsing it later in the same request.
func validateMTLSClientAuthForClient(ctx context.Context, r *http.Request, provider mtlsClientAuthSupport, client Client) (context.Context, error) {
	if client == nil {
		return ctx, oidc.ErrServerError().WithDescription("missing client")
	}
	if provider == nil {
		return ctx, oidc.ErrInvalidClient().WithDescription("mTLS authentication not supported")
	}

	switch client.AuthMethod() {
	case oidc.AuthMethodTLSClientAuth, oidc.AuthMethodSelfSignedTLSClientAuth:
	default:
		return ctx, nil
	}

	certs := ClientCertificateChainFromContext(ctx)
	if len(certs) == 0 {
		var err error
		certs, err = ClientCertificateFromRequest(r, provider.MTLSConfig())
		if err != nil || len(certs) == 0 {
			return ctx, oidc.ErrInvalidClient().WithDescription("no client certificate provided")
		}
		ctx = ContextWithClientCertificateChain(ctx, certs)
	}

	switch client.AuthMethod() {
	case oidc.AuthMethodTLSClientAuth:
		if !provider.AuthMethodTLSClientAuthSupported() {
			return ctx, oidc.ErrInvalidClient().WithDescription("tls_client_auth not supported")
		}
		mtlsClient, ok := client.(HasMTLSConfig)
		if !ok {
			return ctx, oidc.ErrInvalidClient().WithDescription("client does not support mTLS configuration")
		}
		if err := ValidateTLSClientAuth(certs, provider.MTLSConfig(), mtlsClient.GetMTLSConfig()); err != nil {
			return ctx, oidc.ErrInvalidClient().WithDescription("mTLS client authentication failed").WithParent(err)
		}
		return ctx, nil

	case oidc.AuthMethodSelfSignedTLSClientAuth:
		if !provider.AuthMethodSelfSignedTLSClientAuthSupported() {
			return ctx, oidc.ErrInvalidClient().WithDescription("self_signed_tls_client_auth not supported")
		}
		selfSignedClient, ok := client.(HasSelfSignedCertificate)
		if !ok {
			return ctx, oidc.ErrInvalidClient().WithDescription("client does not support self-signed certificates")
		}
		if err := ValidateSelfSignedTLSClientAuth(certs[0], selfSignedClient.GetRegisteredCertificates()); err != nil {
			return ctx, oidc.ErrInvalidClient().WithDescription("mTLS client authentication failed").WithParent(err)
		}
		return ctx, nil
	}

	return ctx, oidc.ErrInvalidClient()
}

// CalculateCertThumbprint calculates the SHA-256 thumbprint of a certificate.
func CalculateCertThumbprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// VerifyCertificateBinding verifies that a certificate matches the expected thumbprint.
func VerifyCertificateBinding(cert *x509.Certificate, expectedThumbprint string) error {
	if cert == nil {
		return errors.New("nil certificate")
	}
	actualThumbprint := CalculateCertThumbprint(cert)
	if actualThumbprint != expectedThumbprint {
		return errors.New("certificate binding mismatch")
	}
	return nil
}

// CreateCertificateBoundClaims creates a cnf claim for a certificate-bound token.
// Returns nil if cert is nil.
func CreateCertificateBoundClaims(cert *x509.Certificate) *CertificateBoundClaims {
	if cert == nil {
		return nil
	}
	return &CertificateBoundClaims{
		Confirmation: &Confirmation{
			X5tS256: CalculateCertThumbprint(cert),
		},
	}
}

// VerifyCertificateBindingWithConfirmation verifies binding against a cnf claim.
// If cnf is nil or cnf.X5tS256 is empty, this is treated as "no binding required".
func VerifyCertificateBindingWithConfirmation(cert *x509.Certificate, cnf *Confirmation) error {
	if cnf == nil || cnf.X5tS256 == "" {
		return nil
	}
	if cert == nil {
		return errors.New("certificate required for bound token")
	}
	return VerifyCertificateBinding(cert, cnf.X5tS256)
}

// GetCnfFromIntrospectionResponse extracts the Confirmation (cnf) claim from
// an introspection response's Claims map.
// Returns nil if not present or invalid format.
func GetCnfFromIntrospectionResponse(claims map[string]any) *Confirmation {
	thumbprint := GetCnfThumbprintFromClaims(claims)
	if thumbprint == "" {
		return nil
	}
	return &Confirmation{X5tS256: thumbprint}
}

// VerifyCertificateBindingForIntrospection verifies that the certificate in the request
// matches the cnf claim from an introspection response.
// This is a convenience function for resource servers using token introspection.
//
// Usage:
//
//	resp, _ := introspectionClient.IntrospectToken(ctx, token)
//	if resp.Active {
//	    if err := op.VerifyCertificateBindingForIntrospection(r, mtlsConfig, resp.Claims); err != nil {
//	        // Certificate binding verification failed
//	    }
//	}
func VerifyCertificateBindingForIntrospection(r *http.Request, mtlsConfig *MTLSConfig, introspectionClaims map[string]any) error {
	thumbprint := GetCnfThumbprintFromClaims(introspectionClaims)
	return VerifyCertificateBindingFromRequest(r, mtlsConfig, thumbprint)
}

// GetCnfThumbprintFromClaims extracts the x5t#S256 thumbprint from a cnf claim map.
// Returns empty string if not found or invalid format.
func GetCnfThumbprintFromClaims(claims map[string]any) string {
	if claims == nil {
		return ""
	}
	cnf, ok := claims["cnf"]
	if !ok {
		return ""
	}
	switch v := cnf.(type) {
	case map[string]any:
		if thumbprint, ok := v["x5t#S256"].(string); ok {
			return thumbprint
		}
	case map[string]string:
		if thumbprint, ok := v["x5t#S256"]; ok {
			return thumbprint
		}
	}
	return ""
}

// VerifyCertificateBindingFromRequest verifies that the certificate in the request
// matches the thumbprint from the token's cnf claim.
// If cnfThumbprint is empty, no binding verification is performed (returns nil).
// This function is used by resource servers (UserInfo, protected resources) to verify
// certificate-bound access tokens per RFC 8705 Section 3.
func VerifyCertificateBindingFromRequest(r *http.Request, mtlsConfig *MTLSConfig, cnfThumbprint string) error {
	if cnfThumbprint == "" {
		return nil // No binding required
	}
	if mtlsConfig == nil {
		return errors.New("mTLS config required for certificate-bound token verification")
	}

	certs, err := ClientCertificateFromRequest(r, mtlsConfig)
	if err != nil {
		return fmt.Errorf("certificate required for bound token: %w", err)
	}
	if len(certs) == 0 {
		return errors.New("certificate required for bound token")
	}

	return VerifyCertificateBinding(certs[0], cnfThumbprint)
}

type cachedRegisteredThumbprint struct {
	thumbprint string
	ok         bool
}

var registeredCertThumbprintCache = newLRU[string, cachedRegisteredThumbprint](1024)

func getRegisteredCertThumbprint(pemCert string) (string, bool) {
	if pemCert == "" {
		return "", false
	}
	if v, ok := registeredCertThumbprintCache.Get(pemCert); ok {
		return v.thumbprint, v.ok
	}

	block, _ := pem.Decode([]byte(pemCert))
	if block == nil || block.Type != "CERTIFICATE" {
		registeredCertThumbprintCache.Add(pemCert, cachedRegisteredThumbprint{ok: false})
		return "", false
	}

	registered, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		registeredCertThumbprintCache.Add(pemCert, cachedRegisteredThumbprint{ok: false})
		return "", false
	}

	thumbprint := CalculateCertThumbprint(registered)
	registeredCertThumbprintCache.Add(pemCert, cachedRegisteredThumbprint{thumbprint: thumbprint, ok: true})
	return thumbprint, true
}

// ValidateSelfSignedTLSClientAuth validates a certificate against registered self-signed certificates.
func ValidateSelfSignedTLSClientAuth(cert *x509.Certificate, registeredCerts []string) error {
	if cert == nil {
		return errors.New("nil certificate")
	}
	certThumbprint := CalculateCertThumbprint(cert)

	for _, pemCert := range registeredCerts {
		if thumbprint, ok := getRegisteredCertThumbprint(pemCert); ok && thumbprint == certThumbprint {
			return nil
		}
	}

	return errors.New("no matching registered certificate")
}
