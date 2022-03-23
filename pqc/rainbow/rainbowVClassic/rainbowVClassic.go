package pqc

import (
	"crypto"
	"crypto/liboqs-go/oqs"
	"io"
	"log"
)

var signer = oqs.Signature{}
var verifier = oqs.Signature{}

const (
	sigName        = "Rainbow-III-Classic"
	PublicKeySize  = 1930600
	PrivateKeySize = 1408736
)

// 公钥
type PublicKey struct {
	Pk []byte
}

// 私钥
type PrivateKey struct {
	PublicKey
	Sk []byte
}

func GenerateKey() (*PrivateKey, error) {
	// fmt.Println("----PQC秘钥对生成开始: ", sigName)

	defer signer.Clean() // clean up even in case of panic

	if err := signer.Init(sigName, nil); err != nil {
		log.Fatal(err)
	}

	sk, pk, err := signer.GenerateKeyPairFinal()

	privateKey := new(PrivateKey)

	privateKey.PublicKey.Pk = pk
	privateKey.Sk = sk

	// fmt.Println("----PQC秘钥对生成结束: ", sigName)
	// fmt.Println("----PQC公钥: ", privateKey.Pk)
	// fmt.Println("----PQC公钥长度: ", len(privateKey.Pk))
	return privateKey, err
}

//func (priv *PrivateKey) Sign(random io.Reader, msg []byte, signer crypto.SignerOpts) ([]byte, error)
func (priv *PrivateKey) SignPQC(msg []byte) (sig []byte, err error) {
	// fmt.Println("----PQC签名开始: ", sigName)

	//defer signer.Clean()

	if err := signer.Init(sigName, priv.Sk); err != nil {
		log.Fatal(err)
	}

	sign, err := signer.Sign(msg)

	// fmt.Println("----PQC签名结束: ", sigName)

	return sign, err
}

func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return priv.SignPQC(digest)
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

//func (pub *PublicKey) Verify(msg []byte, sig []byte) bool
func (pub *PublicKey) Verify(msg []byte, signature []byte) bool {
	return Verify(pub, msg, signature)
}

func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	return true
}

func Verify(pubkey *PublicKey, msg, signature []byte) bool {
	// fmt.Println("----PQC验签开始: ", sigName)

	defer verifier.Clean()

	if err := verifier.Init(sigName, nil); err != nil {
		log.Fatal(err)
		//log.Info(err.Error())
	}

	isValid, err := verifier.Verify(msg, signature, pubkey.Pk)
	if err != nil {
		log.Fatal(err)
		//log.Info(err.Error())
	}

	// fmt.Println("----PQC验签结束: ", sigName)

	return isValid
}
