package x509

import (
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	dilithium5AES "github.com/mercury/mercuryPQCrypto/pqc/dilithium/dilithium5AES"

	//dilithium3AES "github.com/mercury/mercuryPQCrypto/pqc/dilithium/dilithium3AES"

	//"github.com/mercury/mercuryPQCrypto/pqc/falcon/falcon1024"

	falcon512 "github.com/mercury/mercuryPQCrypto/pqc/falcon/falcon512"

	//dilithium2 "github.com/mercury/mercuryPQCrypto/pqc/dilithium/dilithium2"
	//rainbowICircumzenithal "github.com/mercury/mercuryPQCrypto/pqc/rainbow/rainbowICircumzenithal"
	//rainbowIClassic "github.com/mercury/mercuryPQCrypto/pqc/rainbow/rainbowIClassic"
	//rainbowICompressed "github.com/mercury/mercuryPQCrypto/pqc/rainbow/rainbowICompressed"
	//rainbowIIICircumzenithal "github.com/mercury/mercuryPQCrypto/pqc/rainbow/rainbowIIICircumzenithal"
	//rainbowIIIClassic "github.com/mercury/mercuryPQCrypto/pqc/rainbow/rainbowIIIClassic"
	//rainbowIIICompressed "github.com/mercury/mercuryPQCrypto/pqc/rainbow/rainbowIIICompressed"
	//rainbowVCircumzenithal "github.com/mercury/mercuryPQCrypto/pqc/rainbow/rainbowVCircumzenithal"
	//rainbowVClassic "github.com/mercury/mercuryPQCrypto/pqc/rainbow/rainbowVClassic"
	//rainbowVCompressed "github.com/mercury/mercuryPQCrypto/pqc/rainbow/rainbowVCompressed"

	"github.com/mercury/mercuryPQCrypto/rand"
	"github.com/mercury/mercuryPQCrypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"
)

func TestCreateSelfSignedCertificatePQC(t *testing.T) {
	random := rand.Reader

	pqcPriv, err := falcon512.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate pqc key: %s", err)
	}

	testExtKeyUsage := []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")

	commonName := "test.example.com"
	template := Certificate{
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"Test Acme Co"},
			Country:      []string{"US"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Unix(1000, 0),
		NotAfter:  time.Unix(100000, 0),

		SignatureAlgorithm: PureFalcon512,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
		URIs:           []*url.URL{parseURI("https://foo.com/wibble#foo")},

		PolicyIdentifiers:       []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains:     []string{".example.com", "example.com"},
		ExcludedDNSDomains:      []string{"bar.example.com"},
		PermittedIPRanges:       []*net.IPNet{parseCIDR("192.168.1.1/16"), parseCIDR("1.2.3.4/8")},
		ExcludedIPRanges:        []*net.IPNet{parseCIDR("2001:db8::/48")},
		PermittedEmailAddresses: []string{"foo@example.com"},
		ExcludedEmailAddresses:  []string{".example.com", "example.com"},
		PermittedURIDomains:     []string{".bar.com", "bar.com"},
		ExcludedURIDomains:      []string{".bar2.com", "bar2.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       oidExtensionSubjectKeyId,
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}

	derBytes, err := CreateCertificate(random, &template, &template, &pqcPriv.PublicKey, pqcPriv)
	//
	if err != nil {
		t.Errorf("%s: failed to create certificate: %s", "pqc", err)
	}

	cert, err := ParseCertificate(derBytes)

	fmt.Println("cert: ", cert)

	block := pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   derBytes,
	}

	//pem.Decode(derBytes)
	file, err := os.Create("test.crt")
	defer file.Close()
	pem.Encode(file, &block)
}

func TestParsePublicKeyPQC(t *testing.T) {
	const pqcCertPEM = `
-----BEGIN CERTIFICATE-----
MIIJkTCCBu2gAwIBAgIB/zAFBgMpAAAwUDEVMBMGA1UEChMMVGVzdCBBY21lIENv
MRkwFwYDVQQDExB0ZXN0LmV4YW1wbGUuY29tMQ8wDQYDVQQqEwZHb3BoZXIxCzAJ
BgNVBAYTAk5MMB4XDTcwMDEwMTAwMTY0MFoXDTcwMDEwMjAzNDY0MFowUDEVMBMG
A1UEChMMVGVzdCBBY21lIENvMRkwFwYDVQQDExB0ZXN0LmV4YW1wbGUuY29tMQ8w
DQYDVQQqEwZHb3BoZXIxCzAJBgNVBAYTAk5MMIIDjTAFBgMpAAADggOCAAm2zelo
gRGwqPwCShCadXykbjv/5El+0aWnjAz3RsGph2gQBnfazXCc2AV/Mqz2sZZKOgDi
JHpuL7T2N2Pq51qUwuWlViEVaKnvJBEBTxMK5QsR0oFCeOA4+WYZK4wG1bFDhUbm
aVPCTHQ3qApq5AvMNjCzYrLHkqh0Nop3XuWRxeuU7pJwvJ6Ai18DFA1MjrqqR9F6
sl1buqRumOEogGqkkawoZ8Z5WqenhTy5r47sGLKwN1GQ61V0wGcyFP5o/uYwz9Ao
khx25e9e43q6/EvxldJJ7u+kaG8eDNz9kNPpOXjVnmmWRvtn5JuyCB8bKFwC2vwK
em2R6KPZDE5l3a0JYMUTXHIdKmCi17BtuJf01dAFLDKbLmDpL90y1DhDwVyoWOdM
Jqi82HRSnScHUUYZZcMm1kXekjJClRichABCq+jBtfFQ2eoNJYJR1PeBjHtizXs0
+skginI5p8Fl9CUaHPZSTWGqWV5YdAMojGXJWAYV7TMo6th/qJGX4KV7+8bhKXiG
hJiD8KQF+pMF3DqQZMVprMcrdzGaMthD40F1+HAh35RGDAFUKmXAu3YU1+FdTzSS
hEcDV8EgUMvTKheRX2IP91hJLwG0SJLTaH4r3pjzXSCvWPHpoMbhSS1pBWXFZkVj
SRcz/aqUYOVh1BWazL5W5FfN7k14iUoxwyiuomg/dERtwQl6TBJb1J461VRxt1qQ
saKdknWGGXkZwAgfmuA4UkFhGVibpohvFghLWK+M6cTXxeSzvOl7+RW/KoKrtDjd
S5FhoBKzxhyODm8rl4meLDyBo4UdSRqgSLftp+CfgdTWwy3hHkaodkNXj6lelGiJ
ybdtYjbVuGj1glpii8wmbBjqeEiJV+0kcOB2uMJohVYu1LMsW63QC4Ez2Ok5+ss1
3YVqgpboITXsAwF04Eh/n4u9iZOm3xnOXY2DxOhrcijJ0yZ3b7i7XAYmVKBhFKBC
1WOLippi0wCHWIICAd4YJ2nUkuxdasbWN0ZpC7FRlq2HrMYp6OLvd6LhpLVNnHsG
1qt9mclBuY6woS7Ft8JTO8usJkj2suINHSV0BBs2sYXlE1Y0M1ROgrliCKR/bgQH
jbRErBgdTBXRNVHqlAEsjKimz9iraN1KwAL3cWDdIPBSiDJpiARnLY91xkxgVV3c
ZDEm9w5gJkis5NbTJolaoL8jFYquaWreltcg06OCAoUwggKBMA4GA1UdDwEB/wQE
AwICBDAmBgNVHSUEHzAdBggrBgEFBQcDAgYIKwYBBQUHAwEGAioDBgOBCwEwDwYD
VR0TAQH/BAUwAwEB/zBfBggrBgEFBQcBAQRTMFEwIwYIKwYBBQUHMAGGF2h0dHA6
Ly9vY3NwLmV4YW1wbGUuY29tMCoGCCsGAQUFBzAChh5odHRwOi8vY3J0LmV4YW1w
bGUuY29tL2NhMS5jcnQwYgYDVR0RBFswWYIQdGVzdC5leGFtcGxlLmNvbYERZ29w
aGVyQGdvbGFuZy5vcmeHBH8AAAGHECABSGAAACABAAAAAAAAAGiGGmh0dHBzOi8v
Zm9vLmNvbS93aWJibGUjZm9vMA8GA1UdIAQIMAYwBAYCKgMwgd8GA1UdHgSB1zCB
1KBhMA6CDC5leGFtcGxlLmNvbTANggtleGFtcGxlLmNvbTAKhwjAqAAA//8AADAK
hwgBAAAA/wAAADARgQ9mb29AZXhhbXBsZS5jb20wCoYILmJhci5jb20wCYYHYmFy
LmNvbaFvMBGCD2Jhci5leGFtcGxlLmNvbTAihyAgAQ24AAAAAAAAAAAAAAAA////
////AAAAAAAAAAAAADAOgQwuZXhhbXBsZS5jb20wDYELZXhhbXBsZS5jb20wC4YJ
LmJhcjIuY29tMAqGCGJhcjIuY29tMFcGA1UdHwRQME4wJaAjoCGGH2h0dHA6Ly9j
cmwxLmV4YW1wbGUuY29tL2NhMS5jcmwwJaAjoCGGH2h0dHA6Ly9jcmwyLmV4YW1w
bGUuY29tL2NhMS5jcmwwFgYDKgMEBA9leHRyYSBleHRlbnNpb24wDQYDVR0OBAYE
BAQDAgEwBQYDKQAAA4IClQA5NUTgNN8wkrkmGsQCs1su/cckEpqivwVo+xsfXQh7
1jxnBshvKWI1Xnrg/LmarIP41PenUawy8XeVj1ohDFo5DSyQOk7kkrn79TAFLX66
RyHJBnjguXY8xCyM3xMj6IcjptKjqbh7XWUWf5XLp6gqLbiI1tgUk41M2uKyXDds
m8dbNN/Yv2P1SSwY7gwlCxNh50ycwisMjmHHC3VSJTl1yeTQ1KKf0h7OJ6Vrk8LC
bdjlAl7K1eSJ0KE0kcbtSR659fIATvUTAuFJU1oeO0JJb1g7he5Udznjjnii9Svt
e9SPLDNIr6FyjcVTVxyHYRiCAoRv0QJcxnwg+BpdSpDdKGh52J0mp1xmZciHdcU0
TDs0pnKt5ULjiFrgqFNq6EEDEFyn7U9E455tb7MywyBzjKvzH2h4s+hFBgjQLLar
1w0SO268DV3RtunGV08GM9IcWsLToE9SXIVUK06l4mxljMlCnzQtdHGOE8tuPxkJ
hbqMo0TOoAq5oDnv32dChDpwsoMg3Q6G32D1MNSCmTnvyCpEOesnB2YGSr1NatqR
aFSYTetda8Ta6SYxd2GJy618xyrVii+BiIWzFDTZzrO6M+fXIJRY3r8LYx1nED5J
1I6klQIcUXK49ZuxyMg8vW7Db3PnGEcBakCIYyThMO9iViPtxNNwqZU7ClNF5KkZ
eBRfHp3h2aEVu3bSNxHeZWAjZfdDr9HSKNbaVjrTUJKu+IJgkW4Ha9u8EZQUlEf3
4wM0eRlr0vKhqdc6PvEc9t2daIJ9Z/zSE9MMkZWKXJkSPp0NPd+5FrbMVQYGM6ny
WNnMhDUt20XwUBFRJJ2Ni6xnv5edq+v6qewyLaNrd/nhRDHGU/j3Nb2+y8laLfqa
xUThzjQ=
-----END CERTIFICATE-----`

	//block, _ := pem.Decode([]byte(certPEM))
	block, _ := pem.Decode([]byte(pqcCertPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}

	cert, err := ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	fmt.Println("cert: ", cert)

}

func TestCreateCertificateRequestPQC(t *testing.T) {
	random := rand.Reader

	pqcPriv, err := falcon512.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate faclon512 key: %s", err)
	}

	template := CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Σ Acme Co"},
		},
		SignatureAlgorithm: PureFalcon512,
		DNSNames:           []string{"test.example.com"},
		EmailAddresses:     []string{"gopher@golang.org"},
		IPAddresses:        []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},
	}

	derBytes, err := CreateCertificateRequest(random, &template, pqcPriv)
	if err != nil {
		t.Errorf("failed to create certificate request: %s", err)
	} else {
		fmt.Println("CreateCertificateRequest测试通过")
	}

	out, err := ParseCertificateRequest(derBytes)
	if err != nil {
		t.Errorf("failed to create certificate request: %s", err)
	} else {
		fmt.Println("ParseCertificateRequest测试通过")
	}

	err = out.CheckSignature()
	if err != nil {
		t.Errorf("failed to check certificate request signature: %s", err)
	} else {
		fmt.Println("CheckSignature测试通过")
	}

	if out.Subject.CommonName != template.Subject.CommonName {
		t.Errorf("output subject common name and template subject common name don't match")
	} else if len(out.Subject.Organization) != len(template.Subject.Organization) {
		t.Errorf("output subject organisation and template subject organisation don't match")
	} else if len(out.DNSNames) != len(template.DNSNames) {
		t.Errorf("output DNS names and template DNS names don't match")
	} else if len(out.EmailAddresses) != len(template.EmailAddresses) {
		t.Errorf("output email addresses and template email addresses don't match")
	} else if len(out.IPAddresses) != len(template.IPAddresses) {
		t.Errorf("output IP addresses and template IP addresses names don't match")
	}

}

var pemFalcon512Key = `-----BEGIN PUBLIC KEY-----
MIIDjTAFBgMpAAADggOCAAlIWmTo5iOMSnIqaGjPb1Sp33Vug/CIPcB7H+m4mg13
EwCIm1FdpRm130gnVsLTRSrZIdHdwyMFQBU5UwUtwk6F0uvpGYAqMpIbGumY7gzN
/ebBr9WiqCQBO6lCb3bsUIIfl7tuo2eNoGlWufdgql/qdjInd8gR7XOgmMfuQxVS
pqhShNkkYjkZCqztI3f+7BM26jxnqGI56wetH92t0cSER6iGLDrgzn2d8sHF5dwl
NKCt+PXgnQ78JcJAUKdq6fWXMFsPFRDdwYCRU7sdIQqaF91LlWs7o2qrDBZeC5Tk
8gwaV0cSQQNJ3NpI+MgmLvYb843at2FZg+OkFfg6xbL5WagensFbAoGi6X/O2vud
lq0UJDh5i4yQlVw28UmoQo/xGCni3fpL+gKh8W8DPPXZcwIeX2ZYeiZ+qhZI1eei
bYxtKBDXJkXIo69Ulajclv0xxa/X4dMWOsjd9pRKeqyk5OM4otx9URU12ImTIhRS
Y8wBkKhtzetemFaAOmCTbk3oHciWxmRTt3iBv6b2JSgpwFNzmOD5ip29IAMGC63U
UCErITZ4gvKAHM6bKIrNGeTA6E3Be6cxKysc6A1Z0mO4jgiEpB0I5At6EvoTp+At
2CAnr1w6Am2iUeIBT5F+dfbVXwpa3XpIgBCou03V1kAta2ER5SK8AEatOpSlsh1l
lKRB8KKN3D0RY9RB7YQ/mlb1QZNan1ggM45XA7U0CZSqCA4cRIN7uhBwK5qnh4XH
Z7qM+3Xu20oWLgDhoyBchTWd+LaFtrvyj6q/2J5aRKsKlGFxOflr6JwY9bB9gYBD
EeVW1cnVaWs/uKykEVVC0DiCkvOf3fQH8TwDqYD5hGgv1W+gH0ycC0VCnGwfsCvx
0+DetPj4Fn/nRQTmePcXngqVXVGysYNwOjXGdf7jSZspQmnbrCp2OX/L6ivrhCgQ
2F4O7BUA9LsHRy06LqSRCxfuiMy35FWIHY4etnMznPx/EULBJ8jPoWYQ+3Cbohgq
q7HalxBqUibEh9BAGOWlVe6drW0Mo9RI6Q+3os6BLN0pIVhVBnVEpwGUvnOO1MWu
8OHgwiLqA/aadc0rioBRMJkOjYxj9BEI218jcwAtZ2nkjrC0kALup3+v5bfF8WUZ
AuWA2hJn0qBghdHrmeN5tY+KQSGtHFZSFQAUngXu4Al9zRstQDc1cUbqXVTxFNdf
Lg==
-----END PUBLIC KEY-----
`

func TestCreatePublicKeyPem(t *testing.T) {
	pqcPriv, _ := falcon512.GenerateKey()
	bytes, err := MarshalPKIXPublicKey(&pqcPriv.PublicKey)
	if err != nil {
		panic(err)
	}

	block := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}

	pem.Encode(os.Stdout, &block)
}

func TestParsePKIXPublicKeyPQC(t *testing.T) {
	t.Run("Falcon512", func(t *testing.T) {
		pub := testParsePKIXPublicKey(t, pemFalcon512Key)
		_, ok := pub.(*falcon512.PublicKey)
		//fmt.Println("类型: ", pub.(falcon512.PublicKey))
		if !ok {
			t.Errorf("Value returned from ParsePKIXPublicKey was not an Falcon512 public key")
		}
	})
}

func TestMarshalPKCS8PrivateKeyPQC(t *testing.T) {
	//priv, _ := falcon512.GenerateKey()
	//priv, _ := falcon1024.GenerateKey()
	priv, _ := dilithium5AES.GenerateKey()
	fmt.Println("priv1: ", priv.Sk)
	fmt.Println(len(priv.Sk))

	marshalBytes, err := MarshalPKCS8PrivateKey(priv)
	fmt.Println(len(marshalBytes))
	if err != nil {
		fmt.Println("MarshalPKCS8PrivateKey, 有问题")
	}

	priv2, err := ParsePKCS8PrivateKey(marshalBytes)
	if err != nil {
		fmt.Println("ParsePKCS8PrivateKey, 有问题")
	}
	fmt.Println("priv2: ", priv2)

	msg := []byte("This is the message to sign")
	sign, _ := priv.SignPQC(msg)
	isValid := priv.PublicKey.Verify(msg, sign)
	fmt.Println("res: ", isValid)
}

type pkcs8Test struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

func TestMarshalPKCS8PrivateKeyFunctionPQC(t *testing.T) {
	privpqc, _ := falcon512.GenerateKey()

	fmt.Println("priv1: ", privpqc.Sk)
	fmt.Println("sk len: ", len(privpqc.Sk))

	var priv pkcs8Test

	priv.Algo = pkix.AlgorithmIdentifier{
		Algorithm: oidPublicKeyFalcon512,
		Parameters: asn1.RawValue{
			//FullBytes: k.Pk,
			Bytes: privpqc.Pk,
		},
	}
	priv.PrivateKey = privpqc.Sk

	fmt.Println("priv, pkix.AlgorithmIdentifier: ", priv)

	marshalBytes, err := asn1.Marshal(priv)
	if err != nil {
		fmt.Println(err)
	}

	var priv2 pkcs8Test
	_, err = asn1.Unmarshal(marshalBytes, &priv2)

	fmt.Println("priv2: ", priv2)
	pkBytes := priv2.Algo.Parameters.Bytes
	skBytes := priv2.PrivateKey
	if len(pkBytes) != falcon512.PublicKeySize || len(skBytes) != falcon512.PrivateKeySize {
		fmt.Println("秘钥长度错误")
		fmt.Println(len(pkBytes), " => ", falcon512.PublicKeySize)
		fmt.Println(len(skBytes), " => ", falcon512.PrivateKeySize)
	}
	//pk := falcon512.PublicKey{Pk: pkBytes}
	final := falcon512.PrivateKey{
		Sk:        skBytes,
		PublicKey: falcon512.PublicKey{Pk: pkBytes},
	}
	fmt.Println(final)

}
