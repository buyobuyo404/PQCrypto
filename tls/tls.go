// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package tls partially implements TLS 1.2, as specified in RFC 5246,
// and TLS 1.3, as specified in RFC 8446.
package tls

// BUG(agl): The crypto/tls package only implements some countermeasures
// against Lucky13 attacks on CBC-mode encryption, and only on SHA1
// variants. See http://www.isg.rhul.ac.uk/tls/TLStiming.pdf and
// https://www.imperialviolet.org/2013/02/04/luckythirteen.html.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	rainbowVCircumzenithal "crypto/pqc/rainbow/rainbowVCircumzenithal"
	rainbowVClassic "crypto/pqc/rainbow/rainbowVClassic"
	rainbowVCompressed "crypto/pqc/rainbow/rainbowVCompressed"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	falcon1024 "crypto/pqc/falcon/falcon1024"
	"crypto/pqc/falcon/falcon512"

	"crypto/pqc/dilithium/dilithium2"
	dilithium2AES "crypto/pqc/dilithium/dilithium2AES"
	dilithium3 "crypto/pqc/dilithium/dilithium3"
	dilithium3AES "crypto/pqc/dilithium/dilithium3AES"
	dilithium5 "crypto/pqc/dilithium/dilithium5"
	dilithium5AES "crypto/pqc/dilithium/dilithium5AES"

	rainbowIIICircumzenithal "crypto/pqc/rainbow/rainbowIIICircumzenithal"
	rainbowIIIClassic "crypto/pqc/rainbow/rainbowIIIClassic"
	rainbowIIICompressed "crypto/pqc/rainbow/rainbowIIICompressed"
)

// Server returns a new TLS server side connection
// using conn as the underlying transport.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Server(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:   conn,
		config: config,
	}
	c.handshakeFn = c.serverHandshake
	return c
}

// Client returns a new TLS client side connection
// using conn as the underlying transport.
// The config cannot be nil: users must set either ServerName or
// InsecureSkipVerify in the config.
func Client(conn net.Conn, config *Config) *Conn {
	c := &Conn{
		conn:     conn,
		config:   config,
		isClient: true,
	}
	c.handshakeFn = c.clientHandshake
	return c
}

// A listener implements a network listener (net.Listener) for TLS connections.
type listener struct {
	net.Listener
	config *Config
}

// Accept waits for and returns the next incoming TLS connection.
// The returned connection is of type *Conn.
func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.config), nil
}

// NewListener creates a Listener which accepts connections from an inner
// Listener and wraps each connection with Server.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func NewListener(inner net.Listener, config *Config) net.Listener {
	l := new(listener)
	l.Listener = inner
	l.config = config
	return l
}

// Listen creates a TLS listener accepting connections on the
// given network address using net.Listen.
// The configuration config must be non-nil and must include
// at least one certificate or else set GetCertificate.
func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if config == nil || len(config.Certificates) == 0 &&
		config.GetCertificate == nil && config.GetConfigForClient == nil {
		return nil, errors.New("tls: neither Certificates, GetCertificate, nor GetConfigForClient set in Config")
	}
	l, err := net.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(l, config), nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// DialWithDialer connects to the given network address using dialer.Dial and
// then initiates a TLS handshake, returning the resulting TLS connection. Any
// timeout or deadline given in the dialer apply to connection and TLS
// handshake as a whole.
//
// DialWithDialer interprets a nil configuration as equivalent to the zero
// configuration; see the documentation of Config for the defaults.
//
// DialWithDialer uses context.Background internally; to specify the context,
// use Dialer.DialContext with NetDialer set to the desired dialer.
func DialWithDialer(dialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	return dial(context.Background(), dialer, network, addr, config)
}

func dial(ctx context.Context, netDialer *net.Dialer, network, addr string, config *Config) (*Conn, error) {
	if netDialer.Timeout != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, netDialer.Timeout)
		defer cancel()
	}

	if !netDialer.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, netDialer.Deadline)
		defer cancel()
	}

	rawConn, err := netDialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	colonPos := strings.LastIndex(addr, ":")
	if colonPos == -1 {
		colonPos = len(addr)
	}
	hostname := addr[:colonPos]

	if config == nil {
		config = defaultConfig()
	}
	// If no ServerName is set, infer the ServerName
	// from the hostname we're connecting to.
	if config.ServerName == "" {
		// Make a copy to avoid polluting argument or default.
		c := config.Clone()
		c.ServerName = hostname
		config = c
	}

	conn := Client(rawConn, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// Dial connects to the given network address using net.Dial
// and then initiates a TLS handshake, returning the resulting
// TLS connection.
// Dial interprets a nil configuration as equivalent to
// the zero configuration; see the documentation of Config
// for the defaults.
func Dial(network, addr string, config *Config) (*Conn, error) {
	return DialWithDialer(new(net.Dialer), network, addr, config)
}

// Dialer dials TLS connections given a configuration and a Dialer for the
// underlying connection.
type Dialer struct {
	// NetDialer is the optional dialer to use for the TLS connections'
	// underlying TCP connections.
	// A nil NetDialer is equivalent to the net.Dialer zero value.
	NetDialer *net.Dialer

	// Config is the TLS configuration to use for new connections.
	// A nil configuration is equivalent to the zero
	// configuration; see the documentation of Config for the
	// defaults.
	Config *Config
}

// Dial connects to the given network address and initiates a TLS
// handshake, returning the resulting TLS connection.
//
// The returned Conn, if any, will always be of type *Conn.
//
// Dial uses context.Background internally; to specify the context,
// use DialContext.
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *Dialer) netDialer() *net.Dialer {
	if d.NetDialer != nil {
		return d.NetDialer
	}
	return new(net.Dialer)
}

// DialContext connects to the given network address and initiates a TLS
// handshake, returning the resulting TLS connection.
//
// The provided Context must be non-nil. If the context expires before
// the connection is complete, an error is returned. Once successfully
// connected, any expiration of the context will not affect the
// connection.
//
// The returned Conn, if any, will always be of type *Conn.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := dial(ctx, d.netDialer(), network, addr, d.Config)
	if err != nil {
		// Don't return c (a typed nil) in an interface.
		return nil, err
	}
	return c, nil
}

// LoadX509KeyPair reads and parses a public/private key pair from a pair
// of files. The files must contain PEM encoded data. The certificate file
// may contain intermediate certificates following the leaf certificate to
// form a certificate chain. On successful return, Certificate.Leaf will
// be nil because the parsed form of the certificate is not retained.
func LoadX509KeyPair(certFile, keyFile string) (Certificate, error) {
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return Certificate{}, err
	}
	keyPEMBlock, err := os.ReadFile(keyFile)
	if err != nil {
		return Certificate{}, err
	}
	return X509KeyPair(certPEMBlock, keyPEMBlock)
}

// X509KeyPair parses a public/private key pair from a pair of
// PEM encoded data. On successful return, Certificate.Leaf will be nil because
// the parsed form of the certificate is not retained.
func X509KeyPair(certPEMBlock, keyPEMBlock []byte) (Certificate, error) {
	fail := func(err error) (Certificate, error) { return Certificate{}, err }

	var cert Certificate
	var skippedBlockTypes []string
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		} else {
			skippedBlockTypes = append(skippedBlockTypes, certDERBlock.Type)
		}
	}

	if len(cert.Certificate) == 0 {
		if len(skippedBlockTypes) == 0 {
			return fail(errors.New("tls: failed to find any PEM data in certificate input"))
		}
		if len(skippedBlockTypes) == 1 && strings.HasSuffix(skippedBlockTypes[0], "PRIVATE KEY") {
			return fail(errors.New("tls: failed to find certificate PEM data in certificate input, but did find a private key; PEM inputs may have been switched"))
		}
		return fail(fmt.Errorf("tls: failed to find \"CERTIFICATE\" PEM block in certificate input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
	}

	skippedBlockTypes = skippedBlockTypes[:0]
	var keyDERBlock *pem.Block
	for {
		keyDERBlock, keyPEMBlock = pem.Decode(keyPEMBlock)
		if keyDERBlock == nil {
			if len(skippedBlockTypes) == 0 {
				return fail(errors.New("tls: failed to find any PEM data in key input"))
			}
			if len(skippedBlockTypes) == 1 && skippedBlockTypes[0] == "CERTIFICATE" {
				return fail(errors.New("tls: found a certificate rather than a key in the PEM for the private key"))
			}
			return fail(fmt.Errorf("tls: failed to find PEM block with type ending in \"PRIVATE KEY\" in key input after skipping PEM blocks of the following types: %v", skippedBlockTypes))
		}
		if keyDERBlock.Type == "PRIVATE KEY" || strings.HasSuffix(keyDERBlock.Type, " PRIVATE KEY") {
			break
		}
		skippedBlockTypes = append(skippedBlockTypes, keyDERBlock.Type)
	}

	// We don't need to parse the public key for TLS, but we so do anyway
	// to check that it looks sane and matches the private key.
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fail(err)
	}

	cert.PrivateKey, err = parsePrivateKey(keyDERBlock.Bytes)
	if err != nil {
		return fail(err)
	}

	switch pub := x509Cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := cert.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.N.Cmp(priv.N) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case *ecdsa.PublicKey:
		priv, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			return fail(errors.New("tls: private key does not match public key"))
		}
	case ed25519.PublicKey:
		priv, ok := cert.PrivateKey.(ed25519.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type"))
		}
		if !bytes.Equal(priv.Public().(ed25519.PublicKey), pub) {
			return fail(errors.New("tls: private key does not match public key"))
		}

	case *falcon512.PublicKey:
		priv, ok := cert.PrivateKey.(*falcon512.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, falcon512"))
		}

		if !bytes.Equal(priv.Public().(*falcon512.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, falcon512"))
		}
	case *falcon1024.PublicKey:
		priv, ok := cert.PrivateKey.(*falcon1024.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, falcon1024"))
		}

		if !bytes.Equal(priv.Public().(*falcon1024.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, falcon1024"))
		}

	case *dilithium2.PublicKey:
		priv, ok := cert.PrivateKey.(*dilithium2.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, dilithium2"))
		}

		if !bytes.Equal(priv.Public().(*dilithium2.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, dilithium2"))
		}
	case *dilithium3.PublicKey:
		priv, ok := cert.PrivateKey.(*dilithium3.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, dilithium3"))
		}

		if !bytes.Equal(priv.Public().(*dilithium3.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, dilithium3"))
		}
	case *dilithium5.PublicKey:
		priv, ok := cert.PrivateKey.(*dilithium5.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, dilithium5"))
		}

		if !bytes.Equal(priv.Public().(*dilithium5.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, dilithium5"))
		}
	case *dilithium2AES.PublicKey:
		priv, ok := cert.PrivateKey.(*dilithium2AES.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, dilithium2AES"))
		}

		if !bytes.Equal(priv.Public().(*dilithium2AES.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, dilithium2AES"))
		}
	case *dilithium3AES.PublicKey:
		priv, ok := cert.PrivateKey.(*dilithium3AES.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, dilithium3AES"))
		}

		if !bytes.Equal(priv.Public().(*dilithium3AES.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, dilithium3AES"))
		}
	case *dilithium5AES.PublicKey:
		priv, ok := cert.PrivateKey.(*dilithium5AES.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, dilithium5AES"))
		}

		if !bytes.Equal(priv.Public().(*dilithium5AES.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, dilithium5AES"))
		}

	case *rainbowIIIClassic.PublicKey:
		priv, ok := cert.PrivateKey.(*rainbowIIIClassic.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, rainbowIIIClassic"))
		}

		if !bytes.Equal(priv.Public().(*rainbowIIIClassic.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, rainbowIIIClassic"))
		}
	case *rainbowIIICircumzenithal.PublicKey:
		priv, ok := cert.PrivateKey.(*rainbowIIICircumzenithal.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, rainbowIIICircumzenithal"))
		}

		if !bytes.Equal(priv.Public().(*rainbowIIICircumzenithal.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, rainbowIIICircumzenithal"))
		}
	case *rainbowIIICompressed.PublicKey:
		priv, ok := cert.PrivateKey.(*rainbowIIICompressed.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, rainbowIIICompressed"))
		}

		if !bytes.Equal(priv.Public().(*rainbowIIICompressed.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, rainbowIIICompressed"))
		}
	case *rainbowVClassic.PublicKey:
		priv, ok := cert.PrivateKey.(*rainbowVClassic.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, rainbowVClassic"))
		}

		if !bytes.Equal(priv.Public().(*rainbowVClassic.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, rainbowVClassic"))
		}
	case *rainbowVCircumzenithal.PublicKey:
		priv, ok := cert.PrivateKey.(*rainbowVCircumzenithal.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, rainbowVCircumzenithal"))
		}

		if !bytes.Equal(priv.Public().(*rainbowVCircumzenithal.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, rainbowVCircumzenithal"))
		}
	case *rainbowVCompressed.PublicKey:
		priv, ok := cert.PrivateKey.(*rainbowVCompressed.PrivateKey)
		if !ok {
			return fail(errors.New("tls: private key type does not match public key type, rainbowVCompressed"))
		}

		if !bytes.Equal(priv.Public().(*rainbowVCompressed.PublicKey).Pk, pub.Pk) {
			return fail(errors.New("tls: private key does not match public key, rainbowVCompressed"))
		}

	default:
		return fail(errors.New("tls: unknown public key algorithm"))
	}

	return cert, nil
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS #1 private keys by default, while OpenSSL 1.0.0 generates PKCS #8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey,
			*falcon512.PrivateKey, *falcon1024.PrivateKey,
			*dilithium2.PrivateKey, *dilithium3.PrivateKey, *dilithium5.PrivateKey,
			*dilithium2AES.PrivateKey, *dilithium3AES.PrivateKey, *dilithium5AES.PrivateKey,
			*rainbowIIIClassic.PrivateKey, *rainbowIIICircumzenithal.PrivateKey, *rainbowIIICompressed.PrivateKey,
			*rainbowVClassic.PrivateKey, *rainbowVCircumzenithal.PrivateKey, *rainbowVCompressed.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("tls: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}
