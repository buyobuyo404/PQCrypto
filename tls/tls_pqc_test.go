package tls

import (
	"strings"
	"testing"
)

func TestClientHelloInfo_SupportsCertificate_PQC(t *testing.T) {
	//rsaCert := &Certificate{
	//	Certificate: [][]byte{testRSACertificate},
	//	PrivateKey:  testRSAPrivateKey,
	//}
	//pkcs1Cert := &Certificate{
	//	Certificate:                  [][]byte{testRSACertificate},
	//	PrivateKey:                   testRSAPrivateKey,
	//	SupportedSignatureAlgorithms: []SignatureScheme{PKCS1WithSHA1, PKCS1WithSHA256},
	//}
	//ecdsaCert := &Certificate{
	//	// ECDSA P-256 certificate
	//	Certificate: [][]byte{testP256Certificate},
	//	PrivateKey:  testP256PrivateKey,
	//}
	ed25519Cert := &Certificate{
		Certificate: [][]byte{testEd25519Certificate},
		PrivateKey:  testEd25519PrivateKey,
	}
	falcon512Cert := &Certificate{
		Certificate: [][]byte{testFalcon512Certificate},
		PrivateKey:  &testFalcon512PrivateKey,
	}

	tests := []struct {
		c       *Certificate
		chi     *ClientHelloInfo
		wantErr string
	}{
		//{rsaCert, &ClientHelloInfo{
		//	ServerName:        "example.golang",
		//	SignatureSchemes:  []SignatureScheme{PSSWithSHA256},
		//	SupportedVersions: []uint16{VersionTLS13},
		//}, ""},
		//{ecdsaCert, &ClientHelloInfo{
		//	SignatureSchemes:  []SignatureScheme{PSSWithSHA256, ECDSAWithP256AndSHA256},
		//	SupportedVersions: []uint16{VersionTLS13, VersionTLS12},
		//}, ""},
		//{rsaCert, &ClientHelloInfo{
		//	ServerName:        "example.com",
		//	SignatureSchemes:  []SignatureScheme{PSSWithSHA256},
		//	SupportedVersions: []uint16{VersionTLS13},
		//}, "not valid for requested server name"},
		//{ecdsaCert, &ClientHelloInfo{
		//	SignatureSchemes:  []SignatureScheme{ECDSAWithP384AndSHA384},
		//	SupportedVersions: []uint16{VersionTLS13},
		//}, "signature algorithms"},
		//{pkcs1Cert, &ClientHelloInfo{
		//	SignatureSchemes:  []SignatureScheme{PSSWithSHA256, ECDSAWithP256AndSHA256},
		//	SupportedVersions: []uint16{VersionTLS13},
		//}, "signature algorithms"},
		//
		//{rsaCert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
		//	SignatureSchemes:  []SignatureScheme{PKCS1WithSHA1},
		//	SupportedVersions: []uint16{VersionTLS13, VersionTLS12},
		//}, "signature algorithms"},
		//{rsaCert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
		//	SignatureSchemes:  []SignatureScheme{PKCS1WithSHA1},
		//	SupportedVersions: []uint16{VersionTLS13, VersionTLS12},
		//	config: &Config{
		//		MaxVersion: VersionTLS12,
		//	},
		//}, ""}, // Check that mutual version selection works.
		//
		//{ecdsaCert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		//	SupportedCurves:   []CurveID{CurveP256},
		//	SupportedPoints:   []uint8{pointFormatUncompressed},
		//	SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
		//	SupportedVersions: []uint16{VersionTLS12},
		//}, ""},
		//{ecdsaCert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		//	SupportedCurves:   []CurveID{CurveP256},
		//	SupportedPoints:   []uint8{pointFormatUncompressed},
		//	SignatureSchemes:  []SignatureScheme{ECDSAWithP384AndSHA384},
		//	SupportedVersions: []uint16{VersionTLS12},
		//}, ""}, // TLS 1.2 does not restrict curves based on the SignatureScheme.
		//{ecdsaCert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		//	SupportedCurves:   []CurveID{CurveP256},
		//	SupportedPoints:   []uint8{pointFormatUncompressed},
		//	SignatureSchemes:  nil,
		//	SupportedVersions: []uint16{VersionTLS12},
		//}, ""}, // TLS 1.2 comes with default signature schemes.
		//{ecdsaCert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
		//	SupportedCurves:   []CurveID{CurveP256},
		//	SupportedPoints:   []uint8{pointFormatUncompressed},
		//	SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
		//	SupportedVersions: []uint16{VersionTLS12},
		//}, "cipher suite"},
		//{ecdsaCert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		//	SupportedCurves:   []CurveID{CurveP256},
		//	SupportedPoints:   []uint8{pointFormatUncompressed},
		//	SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
		//	SupportedVersions: []uint16{VersionTLS12},
		//	config: &Config{
		//		CipherSuites: []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
		//	},
		//}, "cipher suite"},
		//{ecdsaCert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		//	SupportedCurves:   []CurveID{CurveP384},
		//	SupportedPoints:   []uint8{pointFormatUncompressed},
		//	SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
		//	SupportedVersions: []uint16{VersionTLS12},
		//}, "certificate curve"},
		//{ecdsaCert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		//	SupportedCurves:   []CurveID{CurveP256},
		//	SupportedPoints:   []uint8{1},
		//	SignatureSchemes:  []SignatureScheme{ECDSAWithP256AndSHA256},
		//	SupportedVersions: []uint16{VersionTLS12},
		//}, "doesn't support ECDHE"},
		//{ecdsaCert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		//	SupportedCurves:   []CurveID{CurveP256},
		//	SupportedPoints:   []uint8{pointFormatUncompressed},
		//	SignatureSchemes:  []SignatureScheme{PSSWithSHA256},
		//	SupportedVersions: []uint16{VersionTLS12},
		//}, "signature algorithms"},
		//
		//{ed25519Cert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		//	SupportedCurves:   []CurveID{CurveP256}, // only relevant for ECDHE support
		//	SupportedPoints:   []uint8{pointFormatUncompressed},
		//	SignatureSchemes:  []SignatureScheme{Ed25519},
		//	SupportedVersions: []uint16{VersionTLS12},
		//}, ""},
		{ed25519Cert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP256}, // only relevant for ECDHE support
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SignatureSchemes:  []SignatureScheme{Ed25519},
			SupportedVersions: []uint16{VersionTLS10},
		}, "connection doesn't support Ed25519, or falcon512"},
		//{ed25519Cert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		//	SupportedCurves:   []CurveID{},
		//	SupportedPoints:   []uint8{pointFormatUncompressed},
		//	SignatureSchemes:  []SignatureScheme{Ed25519},
		//	SupportedVersions: []uint16{VersionTLS12},
		//}, "doesn't support ECDHE"},

		//{falcon512Cert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		//	SupportedCurves:   []CurveID{CurveP256}, // only relevant for ECDHE support
		//	SupportedPoints:   []uint8{pointFormatUncompressed},
		//	SignatureSchemes:  []SignatureScheme{Falcon512},
		//	SupportedVersions: []uint16{VersionTLS12},
		//}, ""},
		{falcon512Cert, &ClientHelloInfo{
			CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
			SupportedCurves:   []CurveID{CurveP256}, // only relevant for ECDHE support
			SupportedPoints:   []uint8{pointFormatUncompressed},
			SignatureSchemes:  []SignatureScheme{Falcon512},
			SupportedVersions: []uint16{VersionTLS10},
		}, "connection doesn't support Ed25519, or falcon512"},
		//{falcon512Cert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		//	SupportedCurves:   []CurveID{},
		//	SupportedPoints:   []uint8{pointFormatUncompressed},
		//	SignatureSchemes:  []SignatureScheme{Falcon512},
		//	SupportedVersions: []uint16{VersionTLS12},
		//}, "doesn't support ECDHE"},

		//{rsaCert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		//	SupportedCurves:   []CurveID{CurveP256}, // only relevant for ECDHE support
		//	SupportedPoints:   []uint8{pointFormatUncompressed},
		//	SupportedVersions: []uint16{VersionTLS10},
		//}, ""},
		//{rsaCert, &ClientHelloInfo{
		//	CipherSuites:      []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256},
		//	SupportedVersions: []uint16{VersionTLS12},
		//}, ""}, // static RSA fallback
	}
	for i, tt := range tests {
		err := tt.chi.SupportsCertificate(tt.c)
		switch {
		case tt.wantErr == "" && err != nil:
			t.Errorf("%d: unexpected error: %v", i, err)
		case tt.wantErr != "" && err == nil:
			t.Errorf("%d: unexpected success", i)
		case tt.wantErr != "" && !strings.Contains(err.Error(), tt.wantErr):
			t.Errorf("%d: got error %q, expected %q", i, err, tt.wantErr)
		}
	}
}
