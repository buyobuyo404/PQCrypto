// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	falcon1024 "crypto/pqc/falcon/falcon1024"
	falcon512 "crypto/pqc/falcon/falcon512"

	dilithium2 "crypto/pqc/dilithium/dilithium2"
	dilithium2AES "crypto/pqc/dilithium/dilithium2AES"
	dilithium3 "crypto/pqc/dilithium/dilithium3"
	dilithium3AES "crypto/pqc/dilithium/dilithium3AES"
	dilithium5 "crypto/pqc/dilithium/dilithium5"
	dilithium5AES "crypto/pqc/dilithium/dilithium5AES"

	rainbowIIICircumzenithal "crypto/pqc/rainbow/rainbowIIICircumzenithal"
	rainbowIIIClassic "crypto/pqc/rainbow/rainbowIIIClassic"
	rainbowIIICompressed "crypto/pqc/rainbow/rainbowIIICompressed"
	rainbowVCircumzenithal "crypto/pqc/rainbow/rainbowVCircumzenithal"
	rainbowVClassic "crypto/pqc/rainbow/rainbowVClassic"
	rainbowVCompressed "crypto/pqc/rainbow/rainbowVCompressed"
)

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

// ParsePKCS8PrivateKey parses an unencrypted private key in PKCS #8, ASN.1 DER form.
//
// It returns a *rsa.PrivateKey, a *ecdsa.PrivateKey, or a ed25519.PrivateKey.
// More types might be supported in the future.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func ParsePKCS8PrivateKey(der []byte) (key interface{}, err error) {
	var privKey pkcs8
	_, err = asn1.Unmarshal(der, &privKey)

	if err != nil {
		if _, err := asn1.Unmarshal(der, &ecPrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParseECPrivateKey instead for this key format)")
		}
		if _, err := asn1.Unmarshal(der, &pkcs1PrivateKey{}); err == nil {
			return nil, errors.New("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
		}
		return nil, err
	}
	switch {
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRSA):
		key, err = ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse RSA private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA):
		bytes := privKey.Algo.Parameters.FullBytes
		namedCurveOID := new(asn1.ObjectIdentifier)
		if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
			namedCurveOID = nil
		}
		key, err = parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
		if err != nil {
			return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
		}
		return key, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyEd25519):
		if l := len(privKey.Algo.Parameters.FullBytes); l != 0 {
			return nil, errors.New("x509: invalid Ed25519 private key parameters")
		}
		var curvePrivateKey []byte
		if _, err := asn1.Unmarshal(privKey.PrivateKey, &curvePrivateKey); err != nil {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key: %v", err)
		}
		if l := len(curvePrivateKey); l != ed25519.SeedSize {
			return nil, fmt.Errorf("x509: invalid Ed25519 private key length: %d", l)
		}
		return ed25519.NewKeyFromSeed(curvePrivateKey), nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyFalcon512):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != falcon512.PublicKeySize || len(skBytes) != falcon512.PrivateKeySize {
			return nil, errors.New("x509: invalid falcon512 pk or sk size")
		}
		return &falcon512.PrivateKey{
			Sk:        skBytes,
			PublicKey: falcon512.PublicKey{Pk: pkBytes},
		}, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyFalcon1024):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != falcon1024.PublicKeySize || len(skBytes) != falcon1024.PrivateKeySize {
			return nil, errors.New("x509: invalid falcon1024 pk or sk size")
		}
		return &falcon1024.PrivateKey{
			Sk:        skBytes,
			PublicKey: falcon1024.PublicKey{Pk: pkBytes},
		}, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyDilithium2):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != dilithium2.PublicKeySize || len(skBytes) != dilithium2.PrivateKeySize {
			return nil, errors.New("x509: invalid dilithium2 pk or sk size")
		}
		return &dilithium2.PrivateKey{
			Sk:        skBytes,
			PublicKey: dilithium2.PublicKey{Pk: pkBytes},
		}, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyDilithium3):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != dilithium3.PublicKeySize || len(skBytes) != dilithium3.PrivateKeySize {
			return nil, errors.New("x509: invalid dilithium3 pk or sk size")
		}
		return &dilithium3.PrivateKey{
			Sk:        skBytes,
			PublicKey: dilithium3.PublicKey{Pk: pkBytes},
		}, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyDilithium5):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != dilithium5.PublicKeySize || len(skBytes) != dilithium5.PrivateKeySize {
			return nil, errors.New("x509: invalid dilithium5 pk or sk size")
		}
		return &dilithium5.PrivateKey{
			Sk:        skBytes,
			PublicKey: dilithium5.PublicKey{Pk: pkBytes},
		}, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyDilithium2AES):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != dilithium2AES.PublicKeySize || len(skBytes) != dilithium2AES.PrivateKeySize {
			return nil, errors.New("x509: invalid dilithium2AES pk or sk size")
		}
		return &dilithium2AES.PrivateKey{
			Sk:        skBytes,
			PublicKey: dilithium2AES.PublicKey{Pk: pkBytes},
		}, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyDilithium3AES):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != dilithium3AES.PublicKeySize || len(skBytes) != dilithium3AES.PrivateKeySize {
			return nil, errors.New("x509: invalid dilithium3AES pk or sk size")
		}
		return &dilithium3AES.PrivateKey{
			Sk:        skBytes,
			PublicKey: dilithium3AES.PublicKey{Pk: pkBytes},
		}, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyDilithium5AES):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != dilithium5AES.PublicKeySize || len(skBytes) != dilithium5AES.PrivateKeySize {
			return nil, errors.New("x509: invalid dilithium5AES pk or sk size")
		}
		return &dilithium5AES.PrivateKey{
			Sk:        skBytes,
			PublicKey: dilithium5AES.PublicKey{Pk: pkBytes},
		}, nil

	case privKey.Algo.Algorithm.Equal(oidPublicKeyRainbowIIIClassic):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != rainbowIIIClassic.PublicKeySize || len(skBytes) != rainbowIIIClassic.PrivateKeySize {
			return nil, errors.New("x509: invalid rainbowIIIClassic pk or sk size")
		}
		return &rainbowIIIClassic.PrivateKey{
			Sk:        skBytes,
			PublicKey: rainbowIIIClassic.PublicKey{Pk: pkBytes},
		}, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRainbowIIICircumzenithal):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != rainbowIIICircumzenithal.PublicKeySize || len(skBytes) != rainbowIIICircumzenithal.PrivateKeySize {
			return nil, errors.New("x509: invalid rainbowIIICircumzenithal pk or sk size")
		}
		return &rainbowIIICircumzenithal.PrivateKey{
			Sk:        skBytes,
			PublicKey: rainbowIIICircumzenithal.PublicKey{Pk: pkBytes},
		}, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRainbowIIICompressed):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != rainbowIIICompressed.PublicKeySize || len(skBytes) != rainbowIIICompressed.PrivateKeySize {
			return nil, errors.New("x509: invalid rainbowIIICompressed pk or sk size")
		}
		return &rainbowIIICompressed.PrivateKey{
			Sk:        skBytes,
			PublicKey: rainbowIIICompressed.PublicKey{Pk: pkBytes},
		}, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRainbowVClassic):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != rainbowVClassic.PublicKeySize || len(skBytes) != rainbowVClassic.PrivateKeySize {
			return nil, errors.New("x509: invalid rainbowVClassic pk or sk size")
		}
		return &rainbowVClassic.PrivateKey{
			Sk:        skBytes,
			PublicKey: rainbowVClassic.PublicKey{Pk: pkBytes},
		}, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRainbowVCircumzenithal):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != rainbowVCircumzenithal.PublicKeySize || len(skBytes) != rainbowVCircumzenithal.PrivateKeySize {
			return nil, errors.New("x509: invalid rainbowVCircumzenithal pk or sk size")
		}
		return &rainbowVCircumzenithal.PrivateKey{
			Sk:        skBytes,
			PublicKey: rainbowVCircumzenithal.PublicKey{Pk: pkBytes},
		}, nil
	case privKey.Algo.Algorithm.Equal(oidPublicKeyRainbowVCompressed):
		pkBytes := privKey.Algo.Parameters.Bytes
		skBytes := privKey.PrivateKey
		if len(pkBytes) != rainbowVCompressed.PublicKeySize || len(skBytes) != rainbowVCompressed.PrivateKeySize {
			return nil, errors.New("x509: invalid rainbowVCompressed pk or sk size")
		}
		return &rainbowVCompressed.PrivateKey{
			Sk:        skBytes,
			PublicKey: rainbowVCompressed.PublicKey{Pk: pkBytes},
		}, nil

	default:
		return nil, fmt.Errorf("x509: PKCS#8 wrapping contained private key with unknown algorithm: %v", privKey.Algo.Algorithm)
	}
}

// MarshalPKCS8PrivateKey converts a private key to PKCS #8, ASN.1 DER form.
//
// The following key types are currently supported: *rsa.PrivateKey, *ecdsa.PrivateKey
// and ed25519.PrivateKey. Unsupported key types result in an error.
//
// This kind of key is commonly encoded in PEM blocks of type "PRIVATE KEY".
func MarshalPKCS8PrivateKey(key interface{}) ([]byte, error) {
	var privKey pkcs8

	switch k := key.(type) {
	case *rsa.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyRSA,
			Parameters: asn1.NullRawValue,
		}
		privKey.PrivateKey = MarshalPKCS1PrivateKey(k)

	case *ecdsa.PrivateKey:
		oid, ok := oidFromNamedCurve(k.Curve)
		if !ok {
			return nil, errors.New("x509: unknown curve while marshaling to PKCS#8")
		}

		oidBytes, err := asn1.Marshal(oid)
		if err != nil {
			return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
		}

		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		}

		if privKey.PrivateKey, err = marshalECPrivateKeyWithOID(k, nil); err != nil {
			return nil, errors.New("x509: failed to marshal EC private key while building PKCS#8: " + err.Error())
		}

	case ed25519.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyEd25519,
		}
		curvePrivateKey, err := asn1.Marshal(k.Seed())
		if err != nil {
			return nil, fmt.Errorf("x509: failed to marshal private key: %v", err)
		}
		privKey.PrivateKey = curvePrivateKey

	case *falcon512.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyFalcon512,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk
	case *falcon1024.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyFalcon1024,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk

	case *dilithium2.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyDilithium2,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk
	case *dilithium3.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyDilithium3,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk
	case *dilithium5.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyDilithium5,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk
	case *dilithium2AES.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyDilithium2AES,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk
	case *dilithium3AES.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyDilithium3AES,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk
	case *dilithium5AES.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyDilithium5AES,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk

	case *rainbowIIIClassic.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyRainbowIIIClassic,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk
	case *rainbowIIICircumzenithal.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyRainbowIIICircumzenithal,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk
	case *rainbowIIICompressed.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyRainbowIIICompressed,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk
	case *rainbowVClassic.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyRainbowVClassic,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk
	case *rainbowVCircumzenithal.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyRainbowVCircumzenithal,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk
	case *rainbowVCompressed.PrivateKey:
		privKey.Algo = pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyRainbowVCompressed,
			Parameters: asn1.RawValue{
				Bytes: k.Pk,
			},
		}
		privKey.PrivateKey = k.Sk

	default:
		return nil, fmt.Errorf("x509: unknown key type while marshaling PKCS#8: %T", key)
	}

	return asn1.Marshal(privKey)
}
