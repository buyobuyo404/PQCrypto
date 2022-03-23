# PQCrypto-README
## 1 PQCrypto: Integrating Post Quantum Cryptography into Golang

**PQCrypto** is a cryptography project conducted by Chongqing University, China, which considers crypto agility and integrates [go 1.17.6 crypto](https://github.com/golang/go/tree/master/src/crypto)[^1](a fork of it), [Open Quantum Safe (OQS) liboqs/liboqs-go 0.7.1](https://openquantumsafe.org/)[^2] and [tjfoc gmsm-1.4.1](https://github.com/tjfoc/gmsm)[^3]. This project aims to study the migration and application adaptation of post quantum cryptography (PQC) algorithms and Chinese national commercial cryptography algorithms (sm-series).

We have integrated NIST Post-Quantum Cryptography Standardization round 3 digital signature finalists though OQS liboqs/liboqs-go, including:

- CRYSTALS-Dilithium: Dilithium2, Dilithium3, Dilithium5, Dilithium2-AES, Dilithium3-AES, Dilithium5-AES
- Falcon: Falcon-512, Falcon-1024
- Rainbow: Rainbow-III-Classic, Rainbow-III-Circumzenithal, Rainbow-III-Compressed, Rainbow-V-Classic, Rainbow-V-Circumzenithal, Rainbow-V-Compressed

It's important to note that since a new work[^4] makes key-recovery practical for the Rainbow SL 1 parameters become possible, we will not integrate SL 1 parameters in the future work.

And Chinese national commercial cryptography algorithms by tjfoc gmsm:

- SM2
- SM3
- SM4

Among the above algorithms, the post quantum signature algorithms not only support key generation, signature and verification, but also supports all operations in X509.go and private key format conversion in PKCS8.go. You can follow the instructions on crypto in go 1.17.6 to use them. The interfaces of PQCrypto methods are unchanged compared with go 1.17.6. Currently, the Chinese national commercial cryptography algorithms only supports simple key generation, encryption, decryption, signature, verification, and digest computation.

Now we add pqc to go 1.17.6 crypto:
- x509
- tls
- ocsp

## 2 Usage

### 2.1 Environment Variable

1. OS: ubuntu 18.04 +.
2. GoLang: Please make sure you have installed go 1.17.6 and/or above.
3. liboqs and liboqs-go: Please follow the project instructions of [liboqs](https://github.com/open-quantum-safe/liboqs) and [liboqs-go](https://github.com/open-quantum-safe/liboqs-go)  and configure the corresponding environment variable, both of them must be configured correctly.

### 2.2 Clone the Project

```
git clone https://github.com/buyobuyo404/PQCrypto.git
```

Then delete `crypto` folder, put `PQCrypto` into `$GOROOT/src/` folder, and rename `PQCrypto` to `crypto`.

### 2.3 Note

1. Import Package: when importing PQC algorithm packages, the package aliases need to be displayed, otherwise package conflicts may occur. You can do like this:

```go
import (
	"crypto/pqc/falcon/falcon512"
	falcon1024 "crypto/pqc/falcon/falcon1024"
	
	"crypto/pqc/dilithium/dilithium2"
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
```

## 3 Future Work

1. Integrate NIST Post-Quantum Cryptography Standardization **round 3** submissions digital signature algorithms alternate candidates, public-key encryption and key-establishment finalists and alternate candidates.
2. Keep a close eye on NIST Post-Quantum Cryptography Standardization **round 4** and make quick adjustments accordingly.
3. Implement the algorithms in NIST PQC **round 4** using go.
4. Use this project to study the pqc migration in PKI and blockchain.

## 4 About Us

We are post quantum cryptography research team, from School of Big Data and Software, Chongqing University, China. Our main research fields includes post quantum cryptography and its engineering migration and application.

[^1]: go crypto: Go is an open source programming language that makes it easy to build simple, reliable, and efficient software. Moreover, crypto is the cryptographic module of go, which provides various operations on cryptography and certificates. https://github.com/golang/go/tree/master/src/crypto
[^2]: Open Quantum Safe (OQS) liboqs/liboqs-go 0.7.1: liboqs is an open source C library for quantum-safe cryptographic algorithms and we can use post-quantum algorithms from liboqs in the go languages via liboqs-go wrappers. The project is mainly implemented by Open Quantum Safe (OQS), University of Waterloo. https://openquantumsafe.org/
[^3]: tjfoc gmsm: It is the Chinese national commercial cryptography algorithms go implementation by Suzhou Tongji Blockchain Research Institute. https://github.com/tjfoc/gmsm
[^4]: Breaking Rainbow Takes a Weekend on a Laptop, Ward Beullens https://eprint.iacr.org/2022/214.pdf
