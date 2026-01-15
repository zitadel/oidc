package op_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zitadel/oidc/v3/pkg/op"
)

// =============================================================================
// Test Certificate Generation Helpers
// =============================================================================

type testCertOptions struct {
	subject     pkix.Name
	dnsNames    []string
	ipAddresses []net.IP
	uris        []*url.URL
	emails      []string
	policyOIDs  []asn1.ObjectIdentifier
	extKeyUsage []x509.ExtKeyUsage
	isCA        bool
	parent      *x509.Certificate
	parentKey   *ecdsa.PrivateKey
	notBefore   time.Time
	notAfter    time.Time
}

// Certificate policies extension OID
var oidCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}

// buildCertPoliciesExtension creates a certificate policies extension
func buildCertPoliciesExtension(policyOIDs []asn1.ObjectIdentifier) (pkix.Extension, error) {
	type policyInformation struct {
		PolicyIdentifier asn1.ObjectIdentifier
	}

	var policies []policyInformation
	for _, oid := range policyOIDs {
		policies = append(policies, policyInformation{PolicyIdentifier: oid})
	}

	data, err := asn1.Marshal(policies)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:       oidCertificatePolicies,
		Critical: false,
		Value:    data,
	}, nil
}

func generateTestCert(t *testing.T, opts testCertOptions) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	notBefore := opts.notBefore
	if notBefore.IsZero() {
		notBefore = time.Now().Add(-time.Hour)
	}
	notAfter := opts.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(24 * time.Hour)
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               opts.subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           opts.extKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  opts.isCA,
		DNSNames:              opts.dnsNames,
		IPAddresses:           opts.ipAddresses,
		URIs:                  opts.uris,
		EmailAddresses:        opts.emails,
	}

	// Add policy OIDs as an extension (PolicyIdentifiers field alone doesn't work)
	if len(opts.policyOIDs) > 0 {
		policyExt, err := buildCertPoliciesExtension(opts.policyOIDs)
		require.NoError(t, err)
		template.ExtraExtensions = append(template.ExtraExtensions, policyExt)
	}

	if opts.isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	parent := template
	parentKey := key
	if opts.parent != nil && opts.parentKey != nil {
		parent = opts.parent
		parentKey = opts.parentKey
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func generateTestCA(t *testing.T, subject pkix.Name) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	return generateTestCert(t, testCertOptions{
		subject: subject,
		isCA:    true,
	})
}

func certToPEM(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

func calculateThumbprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// =============================================================================
// MTLSConfig Tests
// =============================================================================

func TestMTLSConfig_Validation(t *testing.T) {
	trustStore := x509.NewCertPool()

		tests := []struct {
			name    string
			config  *op.MTLSConfig
			wantErr string
		}{
		{
			name: "valid direct TLS config",
			config: &op.MTLSConfig{
				TrustStore: trustStore,
			},
			wantErr: "",
		},
		{
			name: "proxy headers without TrustedProxyCIDRs",
			config: &op.MTLSConfig{
				TrustStore:              trustStore,
				EnableProxyHeaders:      true,
				CertificateHeader:       "X-Client-Cert",
				CertificateHeaderFormat: "pem-urlencoded",
				TrustedProxyCIDRs:       nil, // Missing!
			},
			wantErr: "TrustedProxyCIDRs is required when EnableProxyHeaders is true",
		},
		{
			name: "proxy headers without CertificateHeader",
			config: &op.MTLSConfig{
				TrustStore:              trustStore,
				EnableProxyHeaders:      true,
				CertificateHeader:       "", // Missing!
				CertificateHeaderFormat: "pem-urlencoded",
				TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
			},
			wantErr: "CertificateHeader is required when EnableProxyHeaders is true",
		},
		{
			name: "proxy headers without CertificateHeaderFormat",
			config: &op.MTLSConfig{
				TrustStore:              trustStore,
				EnableProxyHeaders:      true,
				CertificateHeader:       "X-Client-Cert",
				CertificateHeaderFormat: "", // Missing!
				TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
			},
			wantErr: "CertificateHeaderFormat is required when EnableProxyHeaders is true",
		},
			{
				name: "valid proxy headers config",
				config: &op.MTLSConfig{
					TrustStore:              trustStore,
					EnableProxyHeaders:      true,
					CertificateHeader:       "X-Client-Cert",
					CertificateHeaderFormat: "pem-urlencoded",
					TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
				},
				wantErr: "",
			},
			{
				name: "proxy headers with unsupported CertificateHeaderFormat",
				config: &op.MTLSConfig{
					TrustStore:              trustStore,
					EnableProxyHeaders:      true,
					CertificateHeader:       "X-Client-Cert",
					CertificateHeaderFormat: "unknown-format",
					TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
				},
				wantErr: "unsupported CertificateHeaderFormat",
			},
		}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := op.ValidateMTLSConfig(tt.config)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// Certificate Extraction Tests
// =============================================================================

func TestClientCertificateFromRequest_TLS(t *testing.T) {
	// Generate test certificate
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders: false,
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, cert, certs[0])
}

func TestClientCertificateFromRequest_TLS_WithChain(t *testing.T) {
	// Generate CA and client cert
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "test-client"},
		parent:    ca,
		parentKey: caKey,
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders: false,
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert, ca},
	}

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 2)
	assert.Equal(t, clientCert, certs[0]) // Leaf first
	assert.Equal(t, ca, certs[1])         // Then intermediate/CA
}

func TestClientCertificateFromRequest_NoCert(t *testing.T) {
	config := &op.MTLSConfig{
		EnableProxyHeaders: false,
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	// No TLS connection state

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
}

func TestClientCertificateFromRequest_Header_Disabled(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders: false, // Disabled
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", url.QueryEscape(certToPEM(cert)))
	// No TLS - should fail because proxy headers are disabled

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
}

func TestClientCertificateFromRequest_Header_UntrustedIP(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"}, // Only 10.x.x.x
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", url.QueryEscape(certToPEM(cert)))
	r.RemoteAddr = "192.168.1.1:12345" // Not in trusted range

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not from trusted proxy")
}

func TestClientCertificateFromRequest_Header_TrustedIP(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", url.QueryEscape(certToPEM(cert)))
	r.RemoteAddr = "10.0.0.1:12345" // In trusted range

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, cert.Subject.CommonName, certs[0].Subject.CommonName)
}

func TestClientCertificateFromRequest_Header_PEMBase64(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-base64",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", base64.StdEncoding.EncodeToString([]byte(certToPEM(cert))))
	r.RemoteAddr = "10.0.0.1:12345"

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

func TestClientCertificateFromRequest_Header_DERBase64(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "der-base64",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", base64.StdEncoding.EncodeToString(cert.Raw))
	r.RemoteAddr = "10.0.0.1:12345"

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

func TestClientCertificateFromRequest_Header_InvalidFormat(t *testing.T) {
	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", "not-valid-pem")
	r.RemoteAddr = "10.0.0.1:12345"

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
}

// =============================================================================
// Certificate Chain Validation Tests
// =============================================================================

func TestValidateCertificateChain_ValidCA(t *testing.T) {
	// Create CA
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA", Organization: []string{"Test Org"}})

	// Create client cert signed by CA
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:     pkix.Name{CommonName: "client.example.com"},
		parent:      ca,
		parentKey:   caKey,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	// Create trust store with CA
	trustStore := x509.NewCertPool()
	trustStore.AddCert(ca)

	globalConfig := &op.MTLSConfig{
		TrustStore: trustStore,
	}

	err := op.ValidateCertificateChain([]*x509.Certificate{clientCert}, globalConfig, nil)
	require.NoError(t, err)
}

func TestValidateCertificateChain_UntrustedCA(t *testing.T) {
	// Create untrusted CA
	untrustedCA, untrustedKey := generateTestCA(t, pkix.Name{CommonName: "Untrusted CA"})

	// Create client cert signed by untrusted CA
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "client.example.com"},
		parent:    untrustedCA,
		parentKey: untrustedKey,
	})

	// Create trust store with different CA
	trustedCA, _ := generateTestCA(t, pkix.Name{CommonName: "Trusted CA"})
	trustStore := x509.NewCertPool()
	trustStore.AddCert(trustedCA)

	globalConfig := &op.MTLSConfig{
		TrustStore: trustStore,
	}

	err := op.ValidateCertificateChain([]*x509.Certificate{clientCert}, globalConfig, nil)
	require.Error(t, err)
}

func TestValidateCertificateChain_ExpiredCert(t *testing.T) {
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})

	// Create expired client cert
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "client.example.com"},
		parent:    ca,
		parentKey: caKey,
		notBefore: time.Now().Add(-48 * time.Hour),
		notAfter:  time.Now().Add(-24 * time.Hour), // Expired
	})

	trustStore := x509.NewCertPool()
	trustStore.AddCert(ca)

	globalConfig := &op.MTLSConfig{
		TrustStore: trustStore,
	}

	err := op.ValidateCertificateChain([]*x509.Certificate{clientCert}, globalConfig, nil)
	require.Error(t, err)
}

func TestValidateCertificateChain_WithIntermediates(t *testing.T) {
	// Create root CA
	rootCA, rootKey := generateTestCA(t, pkix.Name{CommonName: "Root CA"})

	// Create intermediate CA
	intermediateCA, intermediateKey := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "Intermediate CA"},
		isCA:      true,
		parent:    rootCA,
		parentKey: rootKey,
	})

	// Create client cert signed by intermediate
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "client.example.com"},
		parent:    intermediateCA,
		parentKey: intermediateKey,
	})

	// Trust store only has root CA
	trustStore := x509.NewCertPool()
	trustStore.AddCert(rootCA)

	globalConfig := &op.MTLSConfig{
		TrustStore: trustStore,
	}

	// Provide chain: [leaf, intermediate]
	err := op.ValidateCertificateChain([]*x509.Certificate{clientCert, intermediateCA}, globalConfig, nil)
	require.NoError(t, err)
}

func TestValidateCertificateChain_ClientTrustStore(t *testing.T) {
	// Create two CAs
	globalCA, _ := generateTestCA(t, pkix.Name{CommonName: "Global CA"})
	clientCA, clientCAKey := generateTestCA(t, pkix.Name{CommonName: "Client CA"})

	// Create client cert signed by client-specific CA
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "client.example.com"},
		parent:    clientCA,
		parentKey: clientCAKey,
	})

	// Global trust store has only globalCA
	globalTrustStore := x509.NewCertPool()
	globalTrustStore.AddCert(globalCA)

	// Client trust store has clientCA
	clientTrustStore := x509.NewCertPool()
	clientTrustStore.AddCert(clientCA)

	globalConfig := &op.MTLSConfig{
		TrustStore: globalTrustStore,
	}
	clientConfig := &op.MTLSClientConfig{
		ClientTrustStore: clientTrustStore,
	}

	// Should pass because client-specific trust store overrides global
	err := op.ValidateCertificateChain([]*x509.Certificate{clientCert}, globalConfig, clientConfig)
	require.NoError(t, err)
}

// =============================================================================
// Policy OID Validation Tests
// =============================================================================

func TestValidatePolicyOIDs_Match(t *testing.T) {
	requiredOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 13}

	cert, _ := generateTestCert(t, testCertOptions{
		subject:    pkix.Name{CommonName: "test"},
		policyOIDs: []asn1.ObjectIdentifier{requiredOID},
	})

	err := op.ValidatePolicyOIDs(cert, []asn1.ObjectIdentifier{requiredOID})
	require.NoError(t, err)
}

func TestValidatePolicyOIDs_Missing(t *testing.T) {
	requiredOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 13}
	differentOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	cert, _ := generateTestCert(t, testCertOptions{
		subject:    pkix.Name{CommonName: "test"},
		policyOIDs: []asn1.ObjectIdentifier{differentOID},
	})

	err := op.ValidatePolicyOIDs(cert, []asn1.ObjectIdentifier{requiredOID})
	require.Error(t, err)
}

func TestValidatePolicyOIDs_Empty(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
	})

	// Empty required OIDs = skip validation
	err := op.ValidatePolicyOIDs(cert, nil)
	require.NoError(t, err)
}

// =============================================================================
// Extended Key Usage Validation Tests
// =============================================================================

func TestValidateExtKeyUsage_ClientAuth(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject:     pkix.Name{CommonName: "test"},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	err := op.ValidateExtKeyUsage(cert, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	require.NoError(t, err)
}

func TestValidateExtKeyUsage_Missing(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject:     pkix.Name{CommonName: "test"},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, // Wrong EKU
	})

	err := op.ValidateExtKeyUsage(cert, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	require.Error(t, err)
}

func TestValidateExtKeyUsage_Empty(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
	})

	// Empty required EKUs = skip validation
	err := op.ValidateExtKeyUsage(cert, nil)
	require.NoError(t, err)
}

// =============================================================================
// Subject DN Comparison Tests (RFC 4517)
// =============================================================================

func TestSubjectDN_ExactMatch(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName:   "client.example.com",
			Organization: []string{"Example Inc"},
			Country:      []string{"US"},
		},
	})

	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "CN=client.example.com,O=Example Inc,C=US",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.NoError(t, err)
}

func TestSubjectDN_OIDTypes_Match(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName:   "client.example.com",
			Organization: []string{"Example Inc"},
			Country:      []string{"US"},
		},
	})

	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "2.5.4.3=client.example.com,2.5.4.10=Example Inc,2.5.4.6=US",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.NoError(t, err)
}

func TestSubjectDN_UnsupportedAttributeType_Rejected(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName: "client.example.com",
		},
	})

	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "DC=example,CN=client.example.com",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid expected DN")
}

func TestSubjectDN_InvalidOID_Rejected(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName: "client.example.com",
		},
	})

	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "2.5.4.a=client.example.com",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid expected DN")
}

func TestSubjectDN_DifferentOrder_Rejected(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName:   "client.example.com",
			Organization: []string{"Example Inc"},
			Country:      []string{"US"},
		},
	})

	// Different RDN order (C first instead of last)
	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "C=US,O=Example Inc,CN=client.example.com",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.Error(t, err)
}

func TestSubjectDN_CaseNormalization(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName:   "Client.Example.COM",
			Organization: []string{"EXAMPLE INC"},
		},
	})

	// Different case should still match (caseIgnoreMatch)
	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "CN=client.example.com,O=example inc",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.NoError(t, err)
}

func TestSubjectDN_WhitespaceNormalization(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName:   "client.example.com",
			Organization: []string{"Example  Inc"}, // Extra space
		},
	})

	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "CN=client.example.com,O=Example Inc",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.NoError(t, err)
}

// =============================================================================
// SAN Comparison Tests
// =============================================================================

func TestSANDNS_CaseInsensitive(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject:  pkix.Name{CommonName: "test"},
		dnsNames: []string{"Client.Example.COM"},
	})

	clientConfig := &op.MTLSClientConfig{
		SANDNS: "client.example.com",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.NoError(t, err)
}

func TestSANDNS_NoMatch(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject:  pkix.Name{CommonName: "test"},
		dnsNames: []string{"other.example.com"},
	})

	clientConfig := &op.MTLSClientConfig{
		SANDNS: "client.example.com",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.Error(t, err)
}

func TestSANIP_BinaryComparison_IPv4(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject:     pkix.Name{CommonName: "test"},
		ipAddresses: []net.IP{net.ParseIP("192.168.1.100")},
	})

	clientConfig := &op.MTLSClientConfig{
		SANIP: "192.168.1.100",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.NoError(t, err)
}

func TestSANIP_BinaryComparison_IPv6(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject:     pkix.Name{CommonName: "test"},
		ipAddresses: []net.IP{net.ParseIP("2001:db8::1")},
	})

	clientConfig := &op.MTLSClientConfig{
		SANIP: "2001:db8::1",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.NoError(t, err)
}

func TestSANURI_Normalized(t *testing.T) {
	uri, _ := url.Parse("https://Client.Example.COM/path")
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
		uris:    []*url.URL{uri},
	})

	clientConfig := &op.MTLSClientConfig{
		SANURI: "https://client.example.com/path",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.NoError(t, err)
}

func TestSANEmail_LocalExact_DomainInsensitive(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
		emails:  []string{"User@Example.COM"},
	})

	// Local part is case-sensitive, domain is case-insensitive
	clientConfig := &op.MTLSClientConfig{
		SANEmail: "User@example.com",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.NoError(t, err)
}

func TestSANEmail_LocalDifferent_Rejected(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
		emails:  []string{"User@example.com"},
	})

	// Different local part case - should fail
	clientConfig := &op.MTLSClientConfig{
		SANEmail: "user@example.com",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.Error(t, err)
}

func TestSAN_NoWildcard(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject:  pkix.Name{CommonName: "test"},
		dnsNames: []string{"*.example.com"},
	})

	// Wildcard in cert should not match non-wildcard expected
	clientConfig := &op.MTLSClientConfig{
		SANDNS: "client.example.com",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.Error(t, err)
}

// =============================================================================
// Certificate Thumbprint Tests
// =============================================================================

func TestCalculateCertThumbprint(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
	})

	thumbprint := op.CalculateCertThumbprint(cert)
	require.NotEmpty(t, thumbprint)

	// Verify it's base64url encoded
	decoded, err := base64.RawURLEncoding.DecodeString(thumbprint)
	require.NoError(t, err)
	assert.Len(t, decoded, 32) // SHA-256 = 32 bytes
}

func TestVerifyCertificateBinding_Match(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
	})

	thumbprint := calculateThumbprint(cert)

	err := op.VerifyCertificateBinding(cert, thumbprint)
	require.NoError(t, err)
}

func TestVerifyCertificateBinding_Mismatch(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
	})

	wrongThumbprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	err := op.VerifyCertificateBinding(cert, wrongThumbprint)
	require.Error(t, err)
}

// =============================================================================
// Self-Signed Certificate Tests
// =============================================================================

func TestValidateSelfSignedTLSClientAuth_Match(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "self-signed-client"},
	})

	registeredCerts := []string{certToPEM(cert)}

	err := op.ValidateSelfSignedTLSClientAuth(cert, registeredCerts)
	require.NoError(t, err)
}

func TestValidateSelfSignedTLSClientAuth_NoMatch(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "self-signed-client"},
	})

	otherCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "other-client"},
	})

	registeredCerts := []string{certToPEM(otherCert)}

	err := op.ValidateSelfSignedTLSClientAuth(cert, registeredCerts)
	require.Error(t, err)
}

func TestValidateSelfSignedTLSClientAuth_MultipleCerts(t *testing.T) {
	cert1, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "client-1"},
	})
	cert2, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "client-2"},
	})
	cert3, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "client-3"},
	})

	// Register cert1 and cert3
	registeredCerts := []string{certToPEM(cert1), certToPEM(cert3)}

	// cert2 should not match
	err := op.ValidateSelfSignedTLSClientAuth(cert2, registeredCerts)
	require.Error(t, err)

	// cert1 should match
	err = op.ValidateSelfSignedTLSClientAuth(cert1, registeredCerts)
	require.NoError(t, err)

	// cert3 should match
	err = op.ValidateSelfSignedTLSClientAuth(cert3, registeredCerts)
	require.NoError(t, err)
}

// =============================================================================
// Fail-Closed Behavior Tests
// =============================================================================

func TestFailClosed_EmptyTrustStore(t *testing.T) {
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "client"},
		parent:    ca,
		parentKey: caKey,
	})

	// Empty trust store
	globalConfig := &op.MTLSConfig{
		TrustStore: x509.NewCertPool(),
	}

	err := op.ValidateCertificateChain([]*x509.Certificate{clientCert}, globalConfig, nil)
	require.Error(t, err)
}

func TestFailClosed_ProxyUntrustedIP_NoFallback(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", url.QueryEscape(certToPEM(cert)))
	r.RemoteAddr = "192.168.1.1:12345" // Not in trusted range

	// Also set TLS cert - should NOT fall back to this
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not from trusted proxy")
}

// =============================================================================
// XFCC Header Format Tests (Envoy X-Forwarded-Client-Cert)
// =============================================================================

func TestClientCertificateFromRequest_Header_XFCC(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Forwarded-Client-Cert",
		CertificateHeaderFormat: "xfcc",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	// XFCC format: Cert="<url-encoded-pem>"
	xfccValue := fmt.Sprintf(`Cert="%s"`, url.QueryEscape(certToPEM(cert)))

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Forwarded-Client-Cert", xfccValue)
	r.RemoteAddr = "10.0.0.1:12345"

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, cert.Subject.CommonName, certs[0].Subject.CommonName)
}

func TestClientCertificateFromRequest_Header_XFCC_CaseInsensitiveKey(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Forwarded-Client-Cert",
		CertificateHeaderFormat: "xfcc",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	xfccValue := fmt.Sprintf(`cert="%s"`, url.QueryEscape(certToPEM(cert)))

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Forwarded-Client-Cert", xfccValue)
	r.RemoteAddr = "10.0.0.1:12345"

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

func TestClientCertificateFromRequest_Header_XFCC_SubjectWithComma(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Forwarded-Client-Cert",
		CertificateHeaderFormat: "xfcc",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	xfccValue := fmt.Sprintf(`Subject="CN=a,b";Cert="%s"`, url.QueryEscape(certToPEM(cert)))

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Forwarded-Client-Cert", xfccValue)
	r.RemoteAddr = "10.0.0.1:12345"

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

func TestClientCertificateFromRequest_Header_XFCC_MultipleElements_Rejected(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Forwarded-Client-Cert",
		CertificateHeaderFormat: "xfcc",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	xfccValue := fmt.Sprintf(`Cert="%s",Cert="%s"`,
		url.QueryEscape(certToPEM(cert)),
		url.QueryEscape(certToPEM(cert)))

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Forwarded-Client-Cert", xfccValue)
	r.RemoteAddr = "10.0.0.1:12345"

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple XFCC elements")
}

func TestClientCertificateFromRequest_Header_XFCC_WithChain(t *testing.T) {
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "test-client"},
		parent:    ca,
		parentKey: caKey,
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Forwarded-Client-Cert",
		CertificateHeaderFormat: "xfcc",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	// XFCC format with Chain: Cert="<url-encoded-pem>";Chain="<url-encoded-pem>"
	xfccValue := fmt.Sprintf(`Cert="%s";Chain="%s"`,
		url.QueryEscape(certToPEM(clientCert)),
		url.QueryEscape(certToPEM(ca)))

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Forwarded-Client-Cert", xfccValue)
	r.RemoteAddr = "10.0.0.1:12345"

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 2)
	assert.Equal(t, clientCert.Subject.CommonName, certs[0].Subject.CommonName)
	assert.Equal(t, ca.Subject.CommonName, certs[1].Subject.CommonName)
}

func TestClientCertificateFromRequest_Header_XFCC_InvalidFormat(t *testing.T) {
	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Forwarded-Client-Cert",
		CertificateHeaderFormat: "xfcc",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Forwarded-Client-Cert", "invalid-xfcc-format")
	r.RemoteAddr = "10.0.0.1:12345"

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
}

func TestClientCertificateFromRequest_Header_XFCC_NoCertField(t *testing.T) {
	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Forwarded-Client-Cert",
		CertificateHeaderFormat: "xfcc",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	// XFCC without Cert field (only Hash)
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Forwarded-Client-Cert", `Hash=abc123;Subject="CN=test"`)
	r.RemoteAddr = "10.0.0.1:12345"

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
}

// =============================================================================
// ValidateTLSClientAuth Integration Tests
// =============================================================================

func TestValidateTLSClientAuth_FullFlow(t *testing.T) {
	// Create CA
	ca, caKey := generateTestCA(t, pkix.Name{
		CommonName:   "Test CA",
		Organization: []string{"Test Org"},
		Country:      []string{"US"},
	})

	// Required OIDs
	policyOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 13}

	// Create client cert with all required attributes
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName:   "client.example.com",
			Organization: []string{"Client Org"},
			Country:      []string{"US"},
		},
		parent:      ca,
		parentKey:   caKey,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		policyOIDs:  []asn1.ObjectIdentifier{policyOID},
	})

	// Setup trust store
	trustStore := x509.NewCertPool()
	trustStore.AddCert(ca)

	globalConfig := &op.MTLSConfig{
		TrustStore:         trustStore,
		RequiredPolicyOIDs: []asn1.ObjectIdentifier{policyOID},
		RequiredEKUs:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "CN=client.example.com,O=Client Org,C=US",
	}

	// Full validation should pass
	err := op.ValidateTLSClientAuth([]*x509.Certificate{clientCert}, globalConfig, clientConfig)
	require.NoError(t, err)
}

func TestValidateTLSClientAuth_NilClientConfig(t *testing.T) {
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "client"},
		parent:    ca,
		parentKey: caKey,
	})

	trustStore := x509.NewCertPool()
	trustStore.AddCert(ca)
	globalConfig := &op.MTLSConfig{
		TrustStore: trustStore,
	}

	err := op.ValidateTLSClientAuth([]*x509.Certificate{clientCert}, globalConfig, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no client configuration")
}

func TestValidateTLSClientAuth_FailAtChainValidation(t *testing.T) {
	// Create untrusted CA
	untrustedCA, untrustedKey := generateTestCA(t, pkix.Name{CommonName: "Untrusted CA"})

	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "client.example.com"},
		parent:    untrustedCA,
		parentKey: untrustedKey,
	})

	// Trust store with different CA
	trustedCA, _ := generateTestCA(t, pkix.Name{CommonName: "Trusted CA"})
	trustStore := x509.NewCertPool()
	trustStore.AddCert(trustedCA)

	globalConfig := &op.MTLSConfig{
		TrustStore: trustStore,
	}

	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "CN=client.example.com",
	}

	err := op.ValidateTLSClientAuth([]*x509.Certificate{clientCert}, globalConfig, clientConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate chain")
}

func TestValidateTLSClientAuth_FailAtPolicyOID(t *testing.T) {
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})

	// Client cert without required policy OID
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "client.example.com"},
		parent:    ca,
		parentKey: caKey,
	})

	trustStore := x509.NewCertPool()
	trustStore.AddCert(ca)

	requiredOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 2, 1, 3, 13}
	globalConfig := &op.MTLSConfig{
		TrustStore:         trustStore,
		RequiredPolicyOIDs: []asn1.ObjectIdentifier{requiredOID},
	}

	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "CN=client.example.com",
	}

	err := op.ValidateTLSClientAuth([]*x509.Certificate{clientCert}, globalConfig, clientConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy OID")
}

func TestValidateTLSClientAuth_FailAtEKU(t *testing.T) {
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})

	// Client cert with ClientAuth (passes chain validation) but missing CodeSigning
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:     pkix.Name{CommonName: "client.example.com"},
		parent:      ca,
		parentKey:   caKey,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // Has ClientAuth
	})

	trustStore := x509.NewCertPool()
	trustStore.AddCert(ca)

	globalConfig := &op.MTLSConfig{
		TrustStore: trustStore,
		// Require CodeSigning in addition to ClientAuth (which is checked in chain validation)
		RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "CN=client.example.com",
	}

	err := op.ValidateTLSClientAuth([]*x509.Certificate{clientCert}, globalConfig, clientConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EKU")
}

func TestValidateTLSClientAuth_FailAtClientIdentifier(t *testing.T) {
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})

	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "actual-client.example.com"},
		parent:    ca,
		parentKey: caKey,
	})

	trustStore := x509.NewCertPool()
	trustStore.AddCert(ca)

	globalConfig := &op.MTLSConfig{
		TrustStore: trustStore,
	}

	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "CN=expected-client.example.com", // Mismatch!
	}

	err := op.ValidateTLSClientAuth([]*x509.Certificate{clientCert}, globalConfig, clientConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject")
}

func TestValidateTLSClientAuth_ClientSpecificPolicyOID(t *testing.T) {
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})

	globalOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	clientOID := asn1.ObjectIdentifier{5, 6, 7, 8}

	// Cert has global OID but not client-specific OID
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:    pkix.Name{CommonName: "client.example.com"},
		parent:     ca,
		parentKey:  caKey,
		policyOIDs: []asn1.ObjectIdentifier{globalOID}, // Missing clientOID
	})

	trustStore := x509.NewCertPool()
	trustStore.AddCert(ca)

	globalConfig := &op.MTLSConfig{
		TrustStore:         trustStore,
		RequiredPolicyOIDs: []asn1.ObjectIdentifier{globalOID},
	}

	clientConfig := &op.MTLSClientConfig{
		SubjectDN:          "CN=client.example.com",
		RequiredPolicyOIDs: []asn1.ObjectIdentifier{clientOID}, // Additional requirement
	}

	err := op.ValidateTLSClientAuth([]*x509.Certificate{clientCert}, globalConfig, clientConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy OID")
}

func TestValidateTLSClientAuth_ClientSpecificEKU(t *testing.T) {
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})

	// Cert has ClientAuth but client requires CodeSigning too
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:     pkix.Name{CommonName: "client.example.com"},
		parent:      ca,
		parentKey:   caKey,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	trustStore := x509.NewCertPool()
	trustStore.AddCert(ca)

	globalConfig := &op.MTLSConfig{
		TrustStore:   trustStore,
		RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientConfig := &op.MTLSClientConfig{
		SubjectDN:    "CN=client.example.com",
		RequiredEKUs: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}, // Additional requirement
	}

	err := op.ValidateTLSClientAuth([]*x509.Certificate{clientCert}, globalConfig, clientConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EKU")
}

// =============================================================================
// Confirmation (cnf) Claim Tests - RFC 8705 Section 3
// =============================================================================

func TestConfirmation_Serialization(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	thumbprint := op.CalculateCertThumbprint(cert)

	cnf := op.Confirmation{
		X5tS256: thumbprint,
	}

	// Test that the struct can be properly created
	assert.NotEmpty(t, cnf.X5tS256)
	assert.Equal(t, thumbprint, cnf.X5tS256)
}

func TestCreateCertificateBoundClaims(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	claims := op.CreateCertificateBoundClaims(cert)

	require.NotNil(t, claims)
	require.NotNil(t, claims.Confirmation)
	assert.NotEmpty(t, claims.Confirmation.X5tS256)

	// Verify the thumbprint matches
	expectedThumbprint := op.CalculateCertThumbprint(cert)
	assert.Equal(t, expectedThumbprint, claims.Confirmation.X5tS256)
}

func TestCreateCertificateBoundClaims_NilCert(t *testing.T) {
	claims := op.CreateCertificateBoundClaims(nil)
	assert.Nil(t, claims)
}

func TestVerifyCertificateBinding_WithConfirmation(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	// Create confirmation from same cert
	cnf := &op.Confirmation{
		X5tS256: op.CalculateCertThumbprint(cert),
	}

	// Should pass - same cert
	err := op.VerifyCertificateBindingWithConfirmation(cert, cnf)
	require.NoError(t, err)
}

func TestVerifyCertificateBinding_WithConfirmation_Mismatch(t *testing.T) {
	cert1, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "client-1"},
	})
	cert2, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "client-2"},
	})

	// Create confirmation from cert1
	cnf := &op.Confirmation{
		X5tS256: op.CalculateCertThumbprint(cert1),
	}

	// Verify with cert2 - should fail
	err := op.VerifyCertificateBindingWithConfirmation(cert2, cnf)
	require.Error(t, err)
}

func TestVerifyCertificateBinding_NilConfirmation(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	// Nil confirmation should pass (no binding required)
	err := op.VerifyCertificateBindingWithConfirmation(cert, nil)
	require.NoError(t, err)
}

func TestVerifyCertificateBinding_EmptyThumbprint(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	cnf := &op.Confirmation{
		X5tS256: "", // Empty
	}

	// Empty thumbprint in confirmation should pass (no binding)
	err := op.VerifyCertificateBindingWithConfirmation(cert, cnf)
	require.NoError(t, err)
}

// =============================================================================
// Nil/Empty Input Handling Tests
// =============================================================================

func TestValidateMTLSConfig_Nil(t *testing.T) {
	// Nil config should not cause panic
	err := op.ValidateMTLSConfig(nil)
	require.NoError(t, err)
}

func TestClientCertificateFromRequest_NilConfig(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/token", nil)

	_, err := op.ClientCertificateFromRequest(r, nil)
	require.Error(t, err)
}

func TestValidateCertificateChain_EmptyCerts(t *testing.T) {
	trustStore := x509.NewCertPool()
	globalConfig := &op.MTLSConfig{
		TrustStore: trustStore,
	}

	err := op.ValidateCertificateChain([]*x509.Certificate{}, globalConfig, nil)
	require.Error(t, err)
}

func TestValidateCertificateChain_NilCerts(t *testing.T) {
	trustStore := x509.NewCertPool()
	globalConfig := &op.MTLSConfig{
		TrustStore: trustStore,
	}

	err := op.ValidateCertificateChain(nil, globalConfig, nil)
	require.Error(t, err)
}

func TestValidateCertificateChain_NilTrustStore(t *testing.T) {
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "client"},
		parent:    ca,
		parentKey: caKey,
	})

	globalConfig := &op.MTLSConfig{
		TrustStore: nil, // No trust store
	}

	err := op.ValidateCertificateChain([]*x509.Certificate{clientCert}, globalConfig, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust store")
}

func TestValidateClientIdentifier_NilConfig(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
	})

	err := op.ValidateClientIdentifier(cert, nil)
	require.Error(t, err)
}

func TestValidateClientIdentifier_EmptyConfig(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
	})

	// Config with no identifier set
	clientConfig := &op.MTLSClientConfig{}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no client identifier")
}

func TestValidateTLSClientAuth_EmptyCerts(t *testing.T) {
	globalConfig := &op.MTLSConfig{
		TrustStore: x509.NewCertPool(),
	}

	err := op.ValidateTLSClientAuth([]*x509.Certificate{}, globalConfig, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no client certificate")
}

func TestValidatePolicyOIDs_NilCert(t *testing.T) {
	requiredOID := asn1.ObjectIdentifier{1, 2, 3}

	err := op.ValidatePolicyOIDs(nil, []asn1.ObjectIdentifier{requiredOID})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil certificate")
}

// =============================================================================
// Invalid Input Format Tests
// =============================================================================

func TestValidateMTLSConfig_InvalidCIDR(t *testing.T) {
	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"not-a-valid-cidr"},
	}

	err := op.ValidateMTLSConfig(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid CIDR")
}

func TestClientCertificateFromRequest_InvalidRemoteAddr(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", url.QueryEscape(certToPEM(cert)))
	r.RemoteAddr = "invalid-address" // No port, not valid format

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
}

func TestClientCertificateFromRequest_MalformedPEM(t *testing.T) {
	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", url.QueryEscape("-----BEGIN CERTIFICATE-----\ninvalid-base64-data\n-----END CERTIFICATE-----"))
	r.RemoteAddr = "10.0.0.1:12345"

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
}

func TestClientCertificateFromRequest_EmptyHeader(t *testing.T) {
	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", "") // Empty header
	r.RemoteAddr = "10.0.0.1:12345"

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
}

func TestClientCertificateFromRequest_UnsupportedFormat(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "unknown-format", // Unsupported
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", certToPEM(cert))
	r.RemoteAddr = "10.0.0.1:12345"

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
}

func TestSubjectDN_InvalidDNFormat(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
	})

	// Empty CN value - cert has CN=test, config expects CN="" (empty)
	// This should fail because the values don't match
	clientConfig := &op.MTLSClientConfig{
		SubjectDN: "CN=",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	// RFC 4517 distinguishedNameMatch: empty value != "test"
	require.Error(t, err, "empty CN value should not match non-empty cert CN")
}

func TestSANIP_InvalidIPFormat(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject:     pkix.Name{CommonName: "test"},
		ipAddresses: []net.IP{net.ParseIP("192.168.1.1")},
	})

	clientConfig := &op.MTLSClientConfig{
		SANIP: "not-an-ip-address",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.Error(t, err)
}

func TestSANURI_InvalidURIFormat(t *testing.T) {
	uri, _ := url.Parse("https://example.com")
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
		uris:    []*url.URL{uri},
	})

	clientConfig := &op.MTLSClientConfig{
		SANURI: "://invalid-uri",
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.Error(t, err)
}

func TestSANEmail_InvalidEmailFormat(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
		emails:  []string{"user@example.com"},
	})

	clientConfig := &op.MTLSClientConfig{
		SANEmail: "no-at-sign", // Invalid email
	}

	err := op.ValidateClientIdentifier(cert, clientConfig)
	require.Error(t, err)
}

// =============================================================================
// Security Edge Case Tests
// =============================================================================

func TestClientCertificateFromRequest_IPv6TrustedProxy(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"2001:db8::/32"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", url.QueryEscape(certToPEM(cert)))
	r.RemoteAddr = "[2001:db8::1]:12345"

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

func TestClientCertificateFromRequest_IPv6Untrusted(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"2001:db8::/32"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", url.QueryEscape(certToPEM(cert)))
	r.RemoteAddr = "[2001:db9::1]:12345" // Different /32

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not from trusted proxy")
}

func TestClientCertificateFromRequest_MultipleTrustedCIDRs(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
	}

	tests := []struct {
		name       string
		remoteAddr string
		wantErr    bool
	}{
		{"10.x trusted", "10.1.2.3:12345", false},
		{"172.16.x trusted", "172.16.1.1:12345", false},
		{"192.168.x trusted", "192.168.1.1:12345", false},
		{"8.8.8.8 untrusted", "8.8.8.8:12345", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/token", nil)
			r.Header.Set("X-Client-Cert", url.QueryEscape(certToPEM(cert)))
			r.RemoteAddr = tt.remoteAddr

			_, err := op.ClientCertificateFromRequest(r, config)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCertificate_NoEKU(t *testing.T) {
	ca, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})

	// Cert with no EKU at all
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:     pkix.Name{CommonName: "client"},
		parent:      ca,
		parentKey:   caKey,
		extKeyUsage: nil, // No EKU
	})

	trustStore := x509.NewCertPool()
	trustStore.AddCert(ca)

	globalConfig := &op.MTLSConfig{
		TrustStore: trustStore,
	}

	// ValidateCertificateChain uses KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	// which means EKU is NOT enforced at chain validation level.
	// EKU enforcement is handled separately by ValidateExtKeyUsage().
	err := op.ValidateCertificateChain([]*x509.Certificate{clientCert}, globalConfig, nil)
	require.NoError(t, err, "chain validation should pass - EKU enforcement is separate")

	// Verify that EKU enforcement works separately when configured
	err = op.ValidateExtKeyUsage(clientCert, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	require.Error(t, err, "EKU validation should fail for cert without ClientAuth EKU")
}

func TestCertificate_MultipleSANsSameType(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject:  pkix.Name{CommonName: "test"},
		dnsNames: []string{"first.example.com", "second.example.com", "third.example.com"},
	})

	// Should match any of the SANs
	tests := []struct {
		name    string
		sanDNS  string
		wantErr bool
	}{
		{"match first", "first.example.com", false},
		{"match second", "second.example.com", false},
		{"match third", "third.example.com", false},
		{"match none", "other.example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConfig := &op.MTLSClientConfig{
				SANDNS: tt.sanDNS,
			}
			err := op.ValidateClientIdentifier(cert, clientConfig)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestSelfSignedTLSClientAuth_EmptyRegisteredCerts(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "self-signed"},
	})

	err := op.ValidateSelfSignedTLSClientAuth(cert, []string{})
	require.Error(t, err)
}

func TestSelfSignedTLSClientAuth_InvalidPEM(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "self-signed"},
	})

	// Invalid PEM should be skipped, not cause error (but no match)
	registeredCerts := []string{
		"not-valid-pem",
		"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
	}

	err := op.ValidateSelfSignedTLSClientAuth(cert, registeredCerts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching")
}

func TestVerifyCertificateBinding_NilCert(t *testing.T) {
	err := op.VerifyCertificateBinding(nil, "some-thumbprint")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil certificate")
}

func TestCalculateCertThumbprint_Deterministic(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test"},
	})

	// Thumbprint should be deterministic
	tp1 := op.CalculateCertThumbprint(cert)
	tp2 := op.CalculateCertThumbprint(cert)
	tp3 := op.CalculateCertThumbprint(cert)

	assert.Equal(t, tp1, tp2)
	assert.Equal(t, tp2, tp3)
}

// =============================================================================
// XFCC Additional Edge Cases
// =============================================================================

func TestClientCertificateFromRequest_Header_XFCC_MultipleElements(t *testing.T) {
	cert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Forwarded-Client-Cert",
		CertificateHeaderFormat: "xfcc",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	// XFCC with additional fields (Hash, Subject, etc.)
	xfccValue := fmt.Sprintf(`Hash=abc123;Cert="%s";Subject="CN=test-client"`,
		url.QueryEscape(certToPEM(cert)))

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Forwarded-Client-Cert", xfccValue)
	r.RemoteAddr = "10.0.0.1:12345"

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

func TestClientCertificateFromRequest_Header_XFCC_EmptyCert(t *testing.T) {
	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Forwarded-Client-Cert",
		CertificateHeaderFormat: "xfcc",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	// XFCC with empty Cert value
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Forwarded-Client-Cert", `Cert=""`)
	r.RemoteAddr = "10.0.0.1:12345"

	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
}

// =============================================================================
// ValidateMTLSClientConfig Tests
// =============================================================================

func TestValidateMTLSClientConfig_NilConfig(t *testing.T) {
	err := op.ValidateMTLSClientConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no client configuration")
}

func TestValidateMTLSClientConfig_NoIdentifier(t *testing.T) {
	config := &op.MTLSClientConfig{}
	err := op.ValidateMTLSClientConfig(config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no client identifier")
}

func TestValidateMTLSClientConfig_MultipleIdentifiers(t *testing.T) {
	tests := []struct {
		name   string
		config *op.MTLSClientConfig
	}{
		{
			name: "SubjectDN and SANDNS",
			config: &op.MTLSClientConfig{
				SubjectDN: "CN=test",
				SANDNS:    "test.example.com",
			},
		},
		{
			name: "SubjectDN and SANURI",
			config: &op.MTLSClientConfig{
				SubjectDN: "CN=test",
				SANURI:    "https://test.example.com",
			},
		},
		{
			name: "SANDNS and SANIP",
			config: &op.MTLSClientConfig{
				SANDNS: "test.example.com",
				SANIP:  "192.168.1.1",
			},
		},
		{
			name: "All identifiers",
			config: &op.MTLSClientConfig{
				SubjectDN: "CN=test",
				SANDNS:    "test.example.com",
				SANURI:    "https://test.example.com",
				SANIP:     "192.168.1.1",
				SANEmail:  "test@example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := op.ValidateMTLSClientConfig(tt.config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "multiple client identifiers")
		})
	}
}

func TestValidateMTLSClientConfig_ExactlyOneIdentifier(t *testing.T) {
	tests := []struct {
		name   string
		config *op.MTLSClientConfig
	}{
		{
			name:   "SubjectDN only",
			config: &op.MTLSClientConfig{SubjectDN: "CN=test,O=Example,C=US"},
		},
		{
			name:   "SANDNS only",
			config: &op.MTLSClientConfig{SANDNS: "client.example.com"},
		},
		{
			name:   "SANURI only",
			config: &op.MTLSClientConfig{SANURI: "https://client.example.com"},
		},
		{
			name:   "SANIP only",
			config: &op.MTLSClientConfig{SANIP: "192.168.1.100"},
		},
		{
			name:   "SANEmail only",
			config: &op.MTLSClientConfig{SANEmail: "client@example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := op.ValidateMTLSClientConfig(tt.config)
			require.NoError(t, err)
		})
	}
}

// =============================================================================
// Certificate Validity Period Tests
// =============================================================================

func TestCertificate_NotYetValid(t *testing.T) {
	// Create a certificate with notBefore in the future
	caCert, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})

	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName:   "Future Client",
			Organization: []string{"Test Org"},
		},
		notBefore:   time.Now().Add(24 * time.Hour), // Not valid until tomorrow
		notAfter:    time.Now().Add(48 * time.Hour),
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		parent:      caCert,
		parentKey:   caKey,
	})

	trustPool := x509.NewCertPool()
	trustPool.AddCert(caCert)

	globalConfig := &op.MTLSConfig{
		TrustStore: trustPool,
	}

	err := op.ValidateCertificateChain([]*x509.Certificate{clientCert}, globalConfig, nil)
	require.Error(t, err)
}

func TestCertificate_Expired(t *testing.T) {
	// Create an expired certificate
	caCert, caKey := generateTestCA(t, pkix.Name{CommonName: "Test CA"})

	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName:   "Expired Client",
			Organization: []string{"Test Org"},
		},
		notBefore:   time.Now().Add(-48 * time.Hour), // Started 2 days ago
		notAfter:    time.Now().Add(-24 * time.Hour), // Expired yesterday
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		parent:      caCert,
		parentKey:   caKey,
	})

	trustPool := x509.NewCertPool()
	trustPool.AddCert(caCert)

	globalConfig := &op.MTLSConfig{
		TrustStore: trustPool,
	}

	err := op.ValidateCertificateChain([]*x509.Certificate{clientCert}, globalConfig, nil)
	require.Error(t, err)
}

// =============================================================================
// Loopback and Special IP Tests
// =============================================================================

func TestClientCertificateFromRequest_LoopbackIP(t *testing.T) {
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})
	certPEM := certToPEM(clientCert)

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"127.0.0.0/8"},
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", url.QueryEscape(certPEM))
	r.RemoteAddr = "127.0.0.1:12345"

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

func TestClientCertificateFromRequest_SingleIPCIDR(t *testing.T) {
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})
	certPEM := certToPEM(clientCert)

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"10.0.0.1/32"}, // Single IP
	}

	// Request from exact trusted IP
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", url.QueryEscape(certPEM))
	r.RemoteAddr = "10.0.0.1:12345"

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 1)

	// Request from adjacent IP (should fail)
	r2 := httptest.NewRequest(http.MethodPost, "/token", nil)
	r2.Header.Set("X-Client-Cert", url.QueryEscape(certPEM))
	r2.RemoteAddr = "10.0.0.2:12345"

	_, err = op.ClientCertificateFromRequest(r2, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not from trusted proxy")
}

func TestClientCertificateFromRequest_IPv6SingleIP(t *testing.T) {
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})
	certPEM := certToPEM(clientCert)

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"::1/128"}, // IPv6 single IP (localhost)
	}

	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", url.QueryEscape(certPEM))
	r.RemoteAddr = "[::1]:12345"

	certs, err := op.ClientCertificateFromRequest(r, config)
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

// =============================================================================
// Certificate Chain Edge Cases
// =============================================================================

func TestValidateCertificateChain_IntermediateCA(t *testing.T) {
	// Create root CA
	rootCert, rootKey := generateTestCA(t, pkix.Name{CommonName: "Root CA", Organization: []string{"Test"}})

	// Create intermediate CA
	intermediateCert, intermediateKey := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "Intermediate CA", Organization: []string{"Test"}},
		isCA:      true,
		parent:    rootCert,
		parentKey: rootKey,
	})

	// Create client certificate signed by intermediate
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:     pkix.Name{CommonName: "Client", Organization: []string{"Test"}},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		parent:      intermediateCert,
		parentKey:   intermediateKey,
	})

	// Trust only root CA
	trustPool := x509.NewCertPool()
	trustPool.AddCert(rootCert)

	globalConfig := &op.MTLSConfig{
		TrustStore: trustPool,
	}

	// Validate with full chain (client + intermediate)
	err := op.ValidateCertificateChain([]*x509.Certificate{clientCert, intermediateCert}, globalConfig, nil)
	require.NoError(t, err)
}

func TestValidateCertificateChain_MissingIntermediate(t *testing.T) {
	// Create root CA
	rootCert, rootKey := generateTestCA(t, pkix.Name{CommonName: "Root CA", Organization: []string{"Test"}})

	// Create intermediate CA
	intermediateCert, intermediateKey := generateTestCert(t, testCertOptions{
		subject:   pkix.Name{CommonName: "Intermediate CA", Organization: []string{"Test"}},
		isCA:      true,
		parent:    rootCert,
		parentKey: rootKey,
	})

	// Create client certificate signed by intermediate
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject:     pkix.Name{CommonName: "Client", Organization: []string{"Test"}},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		parent:      intermediateCert,
		parentKey:   intermediateKey,
	})

	// Trust only root CA
	trustPool := x509.NewCertPool()
	trustPool.AddCert(rootCert)

	globalConfig := &op.MTLSConfig{
		TrustStore: trustPool,
	}

	// Validate without intermediate - should fail
	err := op.ValidateCertificateChain([]*x509.Certificate{clientCert}, globalConfig, nil)
	require.Error(t, err)
}

// =============================================================================
// Header Parsing Edge Cases
// =============================================================================

func TestClientCertificateFromRequest_HeaderWithWhitespace(t *testing.T) {
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})
	certPEM := certToPEM(clientCert)

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	// URL-encode with leading/trailing spaces (after URL encoding)
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", "  "+url.QueryEscape(certPEM)+"  ")
	r.RemoteAddr = "10.0.0.1:12345"

	// Should handle whitespace gracefully (implementation dependent)
	_, err := op.ClientCertificateFromRequest(r, config)
	// Either succeeds or fails with decoding error, not panic
	if err != nil {
		assert.NotContains(t, err.Error(), "panic")
	}
}

func TestClientCertificateFromRequest_DoubleURLEncoded(t *testing.T) {
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})
	certPEM := certToPEM(clientCert)

	config := &op.MTLSConfig{
		EnableProxyHeaders:      true,
		CertificateHeader:       "X-Client-Cert",
		CertificateHeaderFormat: "pem-urlencoded",
		TrustedProxyCIDRs:       []string{"10.0.0.0/8"},
	}

	// Double URL-encode (common mistake)
	doubleEncoded := url.QueryEscape(url.QueryEscape(certPEM))
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Header.Set("X-Client-Cert", doubleEncoded)
	r.RemoteAddr = "10.0.0.1:12345"

	// Should fail (not interpret as valid cert)
	_, err := op.ClientCertificateFromRequest(r, config)
	require.Error(t, err)
}

// =============================================================================
// Self-Signed Certificate Edge Cases
// =============================================================================

func TestSelfSignedTLSClientAuth_CertWithDifferentKey(t *testing.T) {
	// Create self-signed certificate
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "self-signed-client"},
	})
	certPEM := certToPEM(clientCert)

	// Create another self-signed certificate (same subject but different key)
	otherCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "self-signed-client"},
	})

	// Try to validate with a different certificate registered
	err := op.ValidateSelfSignedTLSClientAuth(otherCert, []string{certPEM})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no matching")
}

func TestSelfSignedTLSClientAuth_MultipleRegisteredCerts(t *testing.T) {
	// Create multiple self-signed certificates
	cert1, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "client-1"},
	})
	cert2, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "client-2"},
	})
	cert3, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "client-3"},
	})

	registeredCerts := []string{
		certToPEM(cert1),
		certToPEM(cert2),
		certToPEM(cert3),
	}

	// Validate each certificate
	err := op.ValidateSelfSignedTLSClientAuth(cert1, registeredCerts)
	require.NoError(t, err)

	err = op.ValidateSelfSignedTLSClientAuth(cert2, registeredCerts)
	require.NoError(t, err)

	err = op.ValidateSelfSignedTLSClientAuth(cert3, registeredCerts)
	require.NoError(t, err)

	// Validate unregistered certificate
	unregisteredCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "unregistered"},
	})
	err = op.ValidateSelfSignedTLSClientAuth(unregisteredCert, registeredCerts)
	require.Error(t, err)
}

// =============================================================================
// OID Validation Edge Cases
// =============================================================================

func TestValidatePolicyOIDs_EmptyOIDList(t *testing.T) {
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	// Empty required OIDs should pass
	err := op.ValidatePolicyOIDs(clientCert, []asn1.ObjectIdentifier{})
	require.NoError(t, err)

	// Nil required OIDs should also pass
	err = op.ValidatePolicyOIDs(clientCert, nil)
	require.NoError(t, err)
}

func TestValidateExtKeyUsage_EmptyEKUList(t *testing.T) {
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{CommonName: "test-client"},
	})

	// Empty required EKUs should pass
	err := op.ValidateExtKeyUsage(clientCert, []x509.ExtKeyUsage{})
	require.NoError(t, err)

	// Nil required EKUs should also pass
	err = op.ValidateExtKeyUsage(clientCert, nil)
	require.NoError(t, err)
}

// =============================================================================
// Subject DN Edge Cases
// =============================================================================

func TestValidateClientIdentifier_SubjectDN_CaseSensitivity(t *testing.T) {
	// Create certificate with specific DN
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName:   "Test Client",
			Organization: []string{"Test Organization"},
			Country:      []string{"US"},
		},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	// Exact match should work
	err := op.ValidateClientIdentifier(clientCert, &op.MTLSClientConfig{
		SubjectDN: "CN=Test Client,O=Test Organization,C=US",
	})
	require.NoError(t, err)

	// Note: RFC 4517 distinguishedNameMatch rules may allow case-insensitive
	// comparison for certain attributes. Different implementations may vary.
	// We test that a completely different value fails.
	err = op.ValidateClientIdentifier(clientCert, &op.MTLSClientConfig{
		SubjectDN: "CN=Different Client,O=Test Organization,C=US",
	})
	require.Error(t, err)
}

func TestValidateClientIdentifier_SubjectDN_SpecialCharacters(t *testing.T) {
	// Create certificate with special characters in DN
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName:   "Test, Client + Special",
			Organization: []string{"Test \"Org\""},
			Country:      []string{"US"},
		},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	// RFC 4514 escaped format
	err := op.ValidateClientIdentifier(clientCert, &op.MTLSClientConfig{
		SubjectDN: "CN=Test\\, Client \\+ Special,O=Test \\\"Org\\\",C=US",
	})
	require.NoError(t, err)
}

// =============================================================================
// Certificate-Bound Token Helper Functions Tests
// =============================================================================

func TestGetCnfThumbprintFromClaims(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]any
		expected string
	}{
		{
			name:     "nil claims",
			claims:   nil,
			expected: "",
		},
		{
			name:     "empty claims",
			claims:   map[string]any{},
			expected: "",
		},
		{
			name: "no cnf claim",
			claims: map[string]any{
				"sub": "user123",
			},
			expected: "",
		},
		{
			name: "cnf claim is not a map",
			claims: map[string]any{
				"cnf": "invalid",
			},
			expected: "",
		},
		{
			name: "cnf claim without x5t#S256",
			claims: map[string]any{
				"cnf": map[string]any{
					"other": "value",
				},
			},
			expected: "",
		},
		{
			name: "cnf claim with x5t#S256 as non-string",
			claims: map[string]any{
				"cnf": map[string]any{
					"x5t#S256": 12345,
				},
			},
			expected: "",
		},
		{
			name: "valid cnf claim",
			claims: map[string]any{
				"cnf": map[string]any{
					"x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2",
				},
			},
			expected: "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := op.GetCnfThumbprintFromClaims(tt.claims)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetCnfFromIntrospectionResponse(t *testing.T) {
	tests := []struct {
		name        string
		claims      map[string]any
		expectNil   bool
		expectedX5t string
	}{
		{
			name:      "nil claims",
			claims:    nil,
			expectNil: true,
		},
		{
			name:      "no cnf claim",
			claims:    map[string]any{"sub": "user"},
			expectNil: true,
		},
		{
			name: "valid cnf claim",
			claims: map[string]any{
				"cnf": map[string]any{
					"x5t#S256": "test-thumbprint",
				},
			},
			expectNil:   false,
			expectedX5t: "test-thumbprint",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := op.GetCnfFromIntrospectionResponse(tt.claims)
			if tt.expectNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.expectedX5t, result.X5tS256)
			}
		})
	}
}

func TestVerifyCertificateBindingFromRequest(t *testing.T) {
	// Generate a test certificate
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName: "Test Client",
		},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	// Calculate the expected thumbprint
	expectedThumbprint := op.CalculateCertThumbprint(clientCert)

	// Create a request with the certificate
	r := httptest.NewRequest(http.MethodPost, "/userinfo", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	mtlsConfig := &op.MTLSConfig{}

	tests := []struct {
		name          string
		request       *http.Request
		mtlsConfig    *op.MTLSConfig
		cnfThumbprint string
		expectError   bool
	}{
		{
			name:          "empty thumbprint - no verification needed",
			request:       r,
			mtlsConfig:    mtlsConfig,
			cnfThumbprint: "",
			expectError:   false,
		},
		{
			name:          "matching thumbprint",
			request:       r,
			mtlsConfig:    mtlsConfig,
			cnfThumbprint: expectedThumbprint,
			expectError:   false,
		},
		{
			name:          "mismatched thumbprint",
			request:       r,
			mtlsConfig:    mtlsConfig,
			cnfThumbprint: "wrong-thumbprint",
			expectError:   true,
		},
		{
			name:          "nil mtls config with thumbprint",
			request:       r,
			mtlsConfig:    nil,
			cnfThumbprint: expectedThumbprint,
			expectError:   true,
		},
		{
			name: "no certificate in request",
			request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/userinfo", nil)
				return req
			}(),
			mtlsConfig:    mtlsConfig,
			cnfThumbprint: expectedThumbprint,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := op.VerifyCertificateBindingFromRequest(tt.request, tt.mtlsConfig, tt.cnfThumbprint)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyCertificateBindingForIntrospection(t *testing.T) {
	// Generate a test certificate
	clientCert, _ := generateTestCert(t, testCertOptions{
		subject: pkix.Name{
			CommonName: "Test Client",
		},
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	// Calculate the expected thumbprint
	expectedThumbprint := op.CalculateCertThumbprint(clientCert)

	// Create a request with the certificate
	r := httptest.NewRequest(http.MethodPost, "/resource", nil)
	r.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{clientCert},
	}

	mtlsConfig := &op.MTLSConfig{}

	tests := []struct {
		name        string
		claims      map[string]any
		expectError bool
	}{
		{
			name:        "nil claims - no verification",
			claims:      nil,
			expectError: false,
		},
		{
			name:        "no cnf claim - no verification",
			claims:      map[string]any{"sub": "user"},
			expectError: false,
		},
		{
			name: "matching cnf claim",
			claims: map[string]any{
				"cnf": map[string]any{
					"x5t#S256": expectedThumbprint,
				},
			},
			expectError: false,
		},
		{
			name: "mismatched cnf claim",
			claims: map[string]any{
				"cnf": map[string]any{
					"x5t#S256": "wrong-thumbprint",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := op.VerifyCertificateBindingForIntrospection(r, mtlsConfig, tt.claims)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
