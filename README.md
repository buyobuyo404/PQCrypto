# mercurycrypto-README



[TOC]

## 1 mercurycrypto水星密码学项目

mercurycrypto：是一个考虑到密码敏捷，且整合了[go-1.14.10](https://github.com/golang/go) crypto模块， [open-quantum-safe-0.7.1](https://github.com/open-quantum-safe/liboqs-go)以及[苏州同济区块链研究院gmsm-1.4.1](https://github.com/tjfoc/gmsm)的密码学项目。其目的是为了后量子密码算法和国密算法在go环境下的迁移与应用适配研究。

当前已经引入到mercurycrypto中的**后量子密码算法**，主要是进入到NIST后量子密码标准化进程第三轮中的签名决赛算法

- CRYSTALS-Dilithium: Dilithium2, Dilithium3, Dilithium5, Dilithium2-AES, Dilithium3-AES, Dilithium5-AES
- Falcon: Falcon-512, Falcon-1024
- Rainbow: Rainbow-I-Classic, Rainbow-I-Circumzenithal, Rainbow-I-Compressed, Rainbow-III-Classic, Rainbow-III-Circumzenithal, Rainbow-III-Compressed, Rainbow-V-Classic, Rainbow-V-Circumzenithal, Rainbow-V-Compressed

**国密算法**有：

- SM2
- SM3
- SM4

在以上涉及到的算法中，后量子签名算法目前不仅支持密钥生成、签名和验签，并且支持X509.go中的全部操作以及pkcs8.go中的私钥格式转换，如何使用可以仿照go 1.14.10中关于crypto的文档说明，mercurycrypto各种方法的接口相较于go 1.14.10没有变化。而关于国密算法现在只支持简单的密钥生成、加密、解密、签名、验签、以及摘要计算等操作。

## 2 使用说明

### 2.1 环境变量

1. 本项目目前仅在ubuntu 18.04中进行过测试

2. go语言的环境变量：请下载go 1.14.10及以上版本，并被配置好相应的环境变量，同时设置好国内代理
3. liboqs-go所需要的环境变量：请按照[liboqs](https://github.com/open-quantum-safe/liboqs)和[liboqs-go](https://github.com/open-quantum-safe/liboqs-go)的项目说明配置好相应的环境，两者所需要的环境**必须**都进行配置

### 2.2 使用注意

1. 导入包设置：使用pqc算法在引入包时，需要显示的为包起别名，否则可能出现包冲突，如：

```go
import (
	falcon1024 "github.com/mercury/mercurycrypto/pqc/falcon/falcon1024"
	falcon512 "github.com/mercury/mercurycrypto/pqc/falcon/falcon512"

	dilithium2 "github.com/mercury/mercurycrypto/pqc/dilithium/dilithium2"
	dilithium2AES "github.com/mercury/mercurycrypto/pqc/dilithium/dilithium2AES"
	dilithium3 "github.com/mercury/mercurycrypto/pqc/dilithium/dilithium3"
	dilithium3AES "github.com/mercury/mercurycrypto/pqc/dilithium/dilithium3AES"
	dilithium5 "github.com/mercury/mercurycrypto/pqc/dilithium/dilithium5"
	dilithium5AES "github.com/mercury/mercurycrypto/pqc/dilithium/dilithium5AES"

	rainbowICircumzenithal "github.com/mercury/mercurycrypto/pqc/rainbow/rainbowICircumzenithal"
	rainbowIClassic "github.com/mercury/mercurycrypto/pqc/rainbow/rainbowIClassic"
	rainbowICompressed "github.com/mercury/mercurycrypto/pqc/rainbow/rainbowICompressed"
	rainbowIIICircumzenithal "github.com/mercury/mercurycrypto/pqc/rainbow/rainbowIIICircumzenithal"
	rainbowIIIClassic "github.com/mercury/mercurycrypto/pqc/rainbow/rainbowIIIClassic"
	rainbowIIICompressed "github.com/mercury/mercurycrypto/pqc/rainbow/rainbowIIICompressed"
	rainbowVCircumzenithal "github.com/mercury/mercurycrypto/pqc/rainbow/rainbowVCircumzenithal"
	rainbowVClassic "github.com/mercury/mercurycrypto/pqc/rainbow/rainbowVClassic"
	rainbowVCompressed "github.com/mercury/mercurycrypto/pqc/rainbow/rainbowVCompressed"
)
```

## 下一步工作计划

to be continued...