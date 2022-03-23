package ocsp

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"reflect"
	"testing"
	"time"
)

func TestOCSPResponseFaclon512(t *testing.T) {
	leafCert, _ := hex.DecodeString(leafCertHex)
	leaf, err := x509.ParseCertificate(leafCert)
	if err != nil {
		t.Fatal(err)
	}

	issuerCert, _ := hex.DecodeString(issuerCertHex)
	issuer, err := x509.ParseCertificate(issuerCert)
	if err != nil {
		t.Fatal(err)
	}

	responderCert, _ := hex.DecodeString(responderCertHex)
	responder, err := x509.ParseCertificate(responderCert)
	if err != nil {
		t.Fatal(err)
	}

	responderPrivateKeyDER, _ := hex.DecodeString(responderPrivateKeyHex)
	responderPrivateKey, err := x509.ParsePKCS1PrivateKey(responderPrivateKeyDER)
	if err != nil {
		t.Fatal(err)
	}

	extensionBytes, _ := hex.DecodeString(ocspExtensionValueHex)
	extensions := []pkix.Extension{
		{
			Id:       ocspExtensionOID,
			Critical: false,
			Value:    extensionBytes,
		},
	}

	thisUpdate := time.Date(2010, 7, 7, 15, 1, 5, 0, time.UTC)
	nextUpdate := time.Date(2010, 7, 7, 18, 35, 17, 0, time.UTC)
	template := Response{
		Status:           Revoked,
		SerialNumber:     leaf.SerialNumber,
		ThisUpdate:       thisUpdate,
		NextUpdate:       nextUpdate,
		RevokedAt:        thisUpdate,
		RevocationReason: KeyCompromise,
		Certificate:      responder,
		ExtraExtensions:  extensions,
	}

	template.IssuerHash = crypto.MD5
	_, err = CreateResponse(issuer, responder, template, responderPrivateKey)
	if err == nil {
		t.Fatal("CreateResponse didn't fail with non-valid template.IssuerHash value crypto.MD5")
	}

	testCases := []struct {
		name       string
		issuerHash crypto.Hash
	}{
		{"Zero value", 0},
		{"crypto.SHA1", crypto.SHA1},
		{"crypto.SHA256", crypto.SHA256},
		{"crypto.SHA384", crypto.SHA384},
		{"crypto.SHA512", crypto.SHA512},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			template.IssuerHash = tc.issuerHash
			responseBytes, err := CreateResponse(issuer, responder, template, responderPrivateKey)
			if err != nil {
				t.Fatalf("CreateResponse failed: %s", err)
			}

			resp, err := ParseResponse(responseBytes, nil)
			if err != nil {
				t.Fatalf("ParseResponse failed: %s", err)
			}

			if !reflect.DeepEqual(resp.ThisUpdate, template.ThisUpdate) {
				t.Errorf("resp.ThisUpdate: got %v, want %v", resp.ThisUpdate, template.ThisUpdate)
			}

			if !reflect.DeepEqual(resp.NextUpdate, template.NextUpdate) {
				t.Errorf("resp.NextUpdate: got %v, want %v", resp.NextUpdate, template.NextUpdate)
			}

			if !reflect.DeepEqual(resp.RevokedAt, template.RevokedAt) {
				t.Errorf("resp.RevokedAt: got %v, want %v", resp.RevokedAt, template.RevokedAt)
			}

			if !reflect.DeepEqual(resp.Extensions, template.ExtraExtensions) {
				t.Errorf("resp.Extensions: got %v, want %v", resp.Extensions, template.ExtraExtensions)
			}

			delay := time.Since(resp.ProducedAt)
			if delay < -time.Hour || delay > time.Hour {
				t.Errorf("resp.ProducedAt: got %s, want close to current time (%s)", resp.ProducedAt, time.Now())
			}

			if resp.Status != template.Status {
				t.Errorf("resp.Status: got %d, want %d", resp.Status, template.Status)
			}

			if resp.SerialNumber.Cmp(template.SerialNumber) != 0 {
				t.Errorf("resp.SerialNumber: got %x, want %x", resp.SerialNumber, template.SerialNumber)
			}

			if resp.RevocationReason != template.RevocationReason {
				t.Errorf("resp.RevocationReason: got %d, want %d", resp.RevocationReason, template.RevocationReason)
			}

			expectedHash := tc.issuerHash
			if tc.issuerHash == 0 {
				expectedHash = crypto.SHA1
			}

			if resp.IssuerHash != expectedHash {
				t.Errorf("resp.IssuerHash: got %d, want %d", resp.IssuerHash, expectedHash)
			}
		})
	}
}
