// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bufio"
	"crypto/ed25519"
	"crypto/pqc/falcon/falcon512"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TLS reference tests run a connection against a reference implementation
// (OpenSSL) of TLS and record the bytes of the resulting connection. The Go
// code, during a test, is configured with deterministic randomness and so the
// reference test can be reproduced exactly in the future.
//
// In order to save everyone who wishes to run the tests from needing the
// reference implementation installed, the reference connections are saved in
// files in the testdata directory. Thus running the tests involves nothing
// external, but creating and updating them requires the reference
// implementation.
//
// Tests can be updated by running them with the -update flag. This will cause
// the test files for failing tests to be regenerated. Since the reference
// implementation will always generate fresh random numbers, large parts of the
// reference connection will always change.

var (
	update  = flag.Bool("update", false, "update golden files on failure")
	fast    = flag.Bool("fast", false, "impose a quick, possibly flaky timeout on recorded tests")
	keyFile = flag.String("keylog", "", "destination file for KeyLogWriter")
)

func runTestAndUpdateIfNeeded(t *testing.T, name string, run func(t *testing.T, update bool), wait bool) {
	success := t.Run(name, func(t *testing.T) {
		if !*update && !wait {
			t.Parallel()
		}
		run(t, false)
	})

	if !success && *update {
		t.Run(name+"#update", func(t *testing.T) {
			run(t, true)
		})
	}
}

// checkOpenSSLVersion ensures that the version of OpenSSL looks reasonable
// before updating the test data.
func checkOpenSSLVersion() error {
	if !*update {
		return nil
	}

	openssl := exec.Command("openssl", "version")
	output, err := openssl.CombinedOutput()
	if err != nil {
		return err
	}

	version := string(output)
	if strings.HasPrefix(version, "OpenSSL 1.1.1") {
		return nil
	}

	println("***********************************************")
	println("")
	println("You need to build OpenSSL 1.1.1 from source in order")
	println("to update the test data.")
	println("")
	println("Configure it with:")
	println("./Configure enable-weak-ssl-ciphers no-shared")
	println("and then add the apps/ directory at the front of your PATH.")
	println("***********************************************")

	return errors.New("version of OpenSSL does not appear to be suitable for updating test data")
}

// recordingConn is a net.Conn that records the traffic that passes through it.
// WriteTo can be used to produce output that can be later be loaded with
// ParseTestData.
type recordingConn struct {
	net.Conn
	sync.Mutex
	flows   [][]byte
	reading bool
}

func (r *recordingConn) Read(b []byte) (n int, err error) {
	if n, err = r.Conn.Read(b); n == 0 {
		return
	}
	b = b[:n]

	r.Lock()
	defer r.Unlock()

	if l := len(r.flows); l == 0 || !r.reading {
		buf := make([]byte, len(b))
		copy(buf, b)
		r.flows = append(r.flows, buf)
	} else {
		r.flows[l-1] = append(r.flows[l-1], b[:n]...)
	}
	r.reading = true
	return
}

func (r *recordingConn) Write(b []byte) (n int, err error) {
	if n, err = r.Conn.Write(b); n == 0 {
		return
	}
	b = b[:n]

	r.Lock()
	defer r.Unlock()

	if l := len(r.flows); l == 0 || r.reading {
		buf := make([]byte, len(b))
		copy(buf, b)
		r.flows = append(r.flows, buf)
	} else {
		r.flows[l-1] = append(r.flows[l-1], b[:n]...)
	}
	r.reading = false
	return
}

// WriteTo writes Go source code to w that contains the recorded traffic.
func (r *recordingConn) WriteTo(w io.Writer) (int64, error) {
	// TLS always starts with a client to server flow.
	clientToServer := true
	var written int64
	for i, flow := range r.flows {
		source, dest := "client", "server"
		if !clientToServer {
			source, dest = dest, source
		}
		n, err := fmt.Fprintf(w, ">>> Flow %d (%s to %s)\n", i+1, source, dest)
		written += int64(n)
		if err != nil {
			return written, err
		}
		dumper := hex.Dumper(w)
		n, err = dumper.Write(flow)
		written += int64(n)
		if err != nil {
			return written, err
		}
		err = dumper.Close()
		if err != nil {
			return written, err
		}
		clientToServer = !clientToServer
	}
	return written, nil
}

func parseTestData(r io.Reader) (flows [][]byte, err error) {
	var currentFlow []byte

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		// If the line starts with ">>> " then it marks the beginning
		// of a new flow.
		if strings.HasPrefix(line, ">>> ") {
			if len(currentFlow) > 0 || len(flows) > 0 {
				flows = append(flows, currentFlow)
				currentFlow = nil
			}
			continue
		}

		// Otherwise the line is a line of hex dump that looks like:
		// 00000170  fc f5 06 bf (...)  |.....X{&?......!|
		// (Some bytes have been omitted from the middle section.)

		if i := strings.IndexByte(line, ' '); i >= 0 {
			line = line[i:]
		} else {
			return nil, errors.New("invalid test data")
		}

		if i := strings.IndexByte(line, '|'); i >= 0 {
			line = line[:i]
		} else {
			return nil, errors.New("invalid test data")
		}

		hexBytes := strings.Fields(line)
		for _, hexByte := range hexBytes {
			val, err := strconv.ParseUint(hexByte, 16, 8)
			if err != nil {
				return nil, errors.New("invalid hex byte in test data: " + err.Error())
			}
			currentFlow = append(currentFlow, byte(val))
		}
	}

	if len(currentFlow) > 0 {
		flows = append(flows, currentFlow)
	}

	return flows, nil
}

// tempFile creates a temp file containing contents and returns its path.
func tempFile(contents string) string {
	file, err := os.CreateTemp("", "go-tls-test")
	if err != nil {
		panic("failed to create temp file: " + err.Error())
	}
	path := file.Name()
	file.WriteString(contents)
	file.Close()
	return path
}

// localListener is set up by TestMain and used by localPipe to create Conn
// pairs like net.Pipe, but connected by an actual buffered TCP connection.
var localListener struct {
	mu   sync.Mutex
	addr net.Addr
	ch   chan net.Conn
}

const localFlakes = 0 // change to 1 or 2 to exercise localServer/localPipe handling of mismatches

func localServer(l net.Listener) {
	for n := 0; ; n++ {
		c, err := l.Accept()
		if err != nil {
			return
		}
		if localFlakes == 1 && n%2 == 0 {
			c.Close()
			continue
		}
		localListener.ch <- c
	}
}

var isConnRefused = func(err error) bool { return false }

func localPipe(t testing.TB) (net.Conn, net.Conn) {
	localListener.mu.Lock()
	defer localListener.mu.Unlock()

	addr := localListener.addr

	var err error
Dialing:
	// We expect a rare mismatch, but probably not 5 in a row.
	for i := 0; i < 5; i++ {
		tooSlow := time.NewTimer(1 * time.Second)
		defer tooSlow.Stop()
		var c1 net.Conn
		c1, err = net.Dial(addr.Network(), addr.String())
		if err != nil {
			if runtime.GOOS == "dragonfly" && (isConnRefused(err) || os.IsTimeout(err)) {
				// golang.org/issue/29583: Dragonfly sometimes returns a spurious
				// ECONNREFUSED or ETIMEDOUT.
				<-tooSlow.C
				continue
			}
			t.Fatalf("localPipe: %v", err)
		}
		if localFlakes == 2 && i == 0 {
			c1.Close()
			continue
		}
		for {
			select {
			case <-tooSlow.C:
				t.Logf("localPipe: timeout waiting for %v", c1.LocalAddr())
				c1.Close()
				continue Dialing

			case c2 := <-localListener.ch:
				if c2.RemoteAddr().String() == c1.LocalAddr().String() {
					return c1, c2
				}
				t.Logf("localPipe: unexpected connection: %v != %v", c2.RemoteAddr(), c1.LocalAddr())
				c2.Close()
			}
		}
	}

	t.Fatalf("localPipe: failed to connect: %v", err)
	panic("unreachable")
}

// zeroSource is an io.Reader that returns an unlimited number of zero bytes.
type zeroSource struct{}

func (zeroSource) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

func allCipherSuites() []uint16 {
	ids := make([]uint16, len(cipherSuites))
	for i, suite := range cipherSuites {
		ids[i] = suite.id
	}

	return ids
}

var testConfig *Config

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	// Cipher suites preferences change based on the architecture. Force them to
	// the version without AES acceleration for test consistency.
	hasAESGCMHardwareSupport = false

	// Set up localPipe.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		l, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open local listener: %v", err)
		os.Exit(1)
	}
	localListener.ch = make(chan net.Conn)
	localListener.addr = l.Addr()
	defer l.Close()
	go localServer(l)

	if err := checkOpenSSLVersion(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
		os.Exit(1)
	}

	testConfig = &Config{
		Time:               func() time.Time { return time.Unix(0, 0) },
		Rand:               zeroSource{},
		Certificates:       make([]Certificate, 2),
		InsecureSkipVerify: true,
		CipherSuites:       allCipherSuites(),
	}
	testConfig.Certificates[0].Certificate = [][]byte{testRSACertificate}
	testConfig.Certificates[0].PrivateKey = testRSAPrivateKey
	testConfig.Certificates[1].Certificate = [][]byte{testSNICertificate}
	testConfig.Certificates[1].PrivateKey = testRSAPrivateKey
	testConfig.BuildNameToCertificate()
	if *keyFile != "" {
		f, err := os.OpenFile(*keyFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic("failed to open -keylog file: " + err.Error())
		}
		testConfig.KeyLogWriter = f
		defer f.Close()
	}

	return m.Run()
}

func testHandshake(t *testing.T, clientConfig, serverConfig *Config) (serverState, clientState ConnectionState, err error) {
	const sentinel = "SENTINEL\n"
	c, s := localPipe(t)
	errChan := make(chan error)
	go func() {
		cli := Client(c, clientConfig)
		err := cli.Handshake()
		if err != nil {
			errChan <- fmt.Errorf("client: %v", err)
			c.Close()
			return
		}
		defer cli.Close()
		clientState = cli.ConnectionState()
		buf, err := io.ReadAll(cli)
		if err != nil {
			t.Errorf("failed to call cli.Read: %v", err)
		}
		if got := string(buf); got != sentinel {
			t.Errorf("read %q from TLS connection, but expected %q", got, sentinel)
		}
		errChan <- nil
	}()
	server := Server(s, serverConfig)
	err = server.Handshake()
	if err == nil {
		serverState = server.ConnectionState()
		if _, err := io.WriteString(server, sentinel); err != nil {
			t.Errorf("failed to call server.Write: %v", err)
		}
		if err := server.Close(); err != nil {
			t.Errorf("failed to call server.Close: %v", err)
		}
		err = <-errChan
	} else {
		s.Close()
		<-errChan
	}
	return
}

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

var testRSACertificate = fromHex("3082024b308201b4a003020102020900e8f09d3fe25beaa6300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a301a310b3009060355040a1302476f310b300906035504031302476f30819f300d06092a864886f70d010101050003818d0030818902818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d70203010001a38193308190300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff0402300030190603551d0e041204109f91161f43433e49a6de6db680d79f60301b0603551d230414301280104813494d137e1631bba301d5acab6e7b30190603551d1104123010820e6578616d706c652e676f6c616e67300d06092a864886f70d01010b0500038181009d30cc402b5b50a061cbbae55358e1ed8328a9581aa938a495a1ac315a1a84663d43d32dd90bf297dfd320643892243a00bccf9c7db74020015faad3166109a276fd13c3cce10c5ceeb18782f16c04ed73bbb343778d0c1cf10fa1d8408361c94c722b9daedb4606064df4c1b33ec0d1bd42d4dbfe3d1360845c21d33be9fae7")

var testRSACertificateIssuer = fromHex("3082021930820182a003020102020900ca5e4e811a965964300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f7430819f300d06092a864886f70d010101050003818d0030818902818100d667b378bb22f34143b6cd2008236abefaf2852adf3ab05e01329e2c14834f5105df3f3073f99dab5442d45ee5f8f57b0111c8cb682fbb719a86944eebfffef3406206d898b8c1b1887797c9c5006547bb8f00e694b7a063f10839f269f2c34fff7a1f4b21fbcd6bfdfb13ac792d1d11f277b5c5b48600992203059f2a8f8cc50203010001a35d305b300e0603551d0f0101ff040403020204301d0603551d250416301406082b0601050507030106082b06010505070302300f0603551d130101ff040530030101ff30190603551d0e041204104813494d137e1631bba301d5acab6e7b300d06092a864886f70d01010b050003818100c1154b4bab5266221f293766ae4138899bd4c5e36b13cee670ceeaa4cbdf4f6679017e2fe649765af545749fe4249418a56bd38a04b81e261f5ce86b8d5c65413156a50d12449554748c59a30c515bc36a59d38bddf51173e899820b282e40aa78c806526fd184fb6b4cf186ec728edffa585440d2b3225325f7ab580e87dd76")

// testRSAPSSCertificate has signatureAlgorithm rsassaPss, but subjectPublicKeyInfo
// algorithm rsaEncryption, for use with the rsa_pss_rsae_* SignatureSchemes.
// See also TestRSAPSSKeyError. testRSAPSSCertificate is self-signed.
var testRSAPSSCertificate = fromHex("308202583082018da003020102021100f29926eb87ea8a0db9fcc247347c11b0304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012030123110300e060355040a130741636d6520436f301e170d3137313132333136313631305a170d3138313132333136313631305a30123110300e060355040a130741636d6520436f30819f300d06092a864886f70d010101050003818d0030818902818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d70203010001a3463044300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000300f0603551d110408300687047f000001304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a20302012003818100cdac4ef2ce5f8d79881042707f7cbf1b5a8a00ef19154b40151771006cd41626e5496d56da0c1a139fd84695593cb67f87765e18aa03ea067522dd78d2a589b8c92364e12838ce346c6e067b51f1a7e6f4b37ffab13f1411896679d18e880e0ba09e302ac067efca460288e9538122692297ad8093d4f7dd701424d7700a46a1")

var testECDSACertificate = fromHex("30820990308206eda0030201020201ff30050603290000305031153013060355040a130c546573742041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d310f300d060355042a1306476f70686572310b3009060355040613024e4c301e170d3730303130313030313634305a170d3730303130323033343634305a305031153013060355040a130c546573742041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d310f300d060355042a1306476f70686572310b3009060355040613024e4c3082038d30050603290000038203820009b3b0a1a15202c37fc27e09e1a81b1afaef21ddca04a3791a9504d0fe0496a1095d8ddd291dc963b06f1702feb28237590906fd88a75dd3355a154be3f389c94e16dea582afc37be08af98516fb1b8650fb3461fa9c4a04f7d5a25a9be81fb793a0555f21f711358fb0099242b36b1e8fae6c2c70d813bb6ca09449075cb21396e3b40c250578b60afb1980615774b5a49ba12d4771e4e4d0a86aae5a43f4654def8bc4523523d258b4fe9696f499946a7c53e62e1bc43eee0361d229351b4205b4f19a474fc691d716ab91116c5138b6090faaaad705a9c34b8179fd644c2afd110080216683456784afd9ff10398cea0702a2c6325989bd03bdc2ad57f17179c69e8e905dcbd0815d5dad0887fb054cbb8080f999a2d8cc0c986f72c043a29e95c9c39dc6b69568fdf9e90d3c1c8456372a8b6725cac6579f98c86d0d9a6ace203c92248967be180918d601db0d1eae3d75eed9901c57adbeb6e96d1a290170ed301fcbb4b02430011680ef2ba20ef0be5b8a1086ef26addfde55599ca7c9cd347495acf2708e618d1c1b301ea56721d88f529ad8ce4b1ded17e4abd96f9df8a0fdaa600a3661e53ad5f240b2d1556288c201d8a382f8cd82370c0942aeaf971860a8c9f4a71a9c991903dd949fb275920930e5c2bed62216d646efa39230811c6014b0ee054903845a2705a88a390d284490bd94c748df5a1e46c7cd5727382eed970544e197ac4bc02d4085054994e85f6313569de018c0579446761bc3a3164e7cb06c7928d8cf2094a656cb2844a0d896a70b86eb5dde18a767d6c863dc4f5b56c00204d9d7264e979e2fa1467030411685fa0cb52502ee03e1517a53eb4e8e2157fa2b04d8a4d402d1992f958a957ca21f017660f14e904950c47179d06a392f660db5f1e95e26269a05f603fa6c1500da56265b8e2e5246d4f44120e555545f16b0d41abbfce64756e4016d953103134d1a334009d12b1b0f64a6bce89adf589e89b793b601551b74e5ba8566bb2e95b1551597577c20e9f1afef9021e6ea34ae56619dd185c83ec65669c29aab8564f00c85f51bf614079e72a8315ed6b9b7d8a910898c6e391886427e4984792ef0f0df2cea453cb90040dec020b44c97659cda5681f5092bcce5bbfdd0bb28484262a1d5d3f456259e0095c1c1e696280117b7f3558f8a98b93b32ea9748648922b40a3e2fea0a02c327e4ba49c477e8a1fd6b52a6f79464671d0465ab591bf995fa548222df60618ac30550cc59a382028530820281300e0603551d0f0101ff04040302020430260603551d25041f301d06082b0601050507030206082b0601050507030106022a030603810b01300f0603551d130101ff040530030101ff305f06082b0601050507010104533051302306082b060105050730018617687474703a2f2f6f6373702e6578616d706c652e636f6d302a06082b06010505073002861e687474703a2f2f6372742e6578616d706c652e636f6d2f6361312e63727430620603551d11045b30598210746573742e6578616d706c652e636f6d8111676f7068657240676f6c616e672e6f726787047f000001871020014860000020010000000000000068861a68747470733a2f2f666f6f2e636f6d2f776962626c6523666f6f300f0603551d2004083006300406022a033081df0603551d1e0481d73081d4a061300e820c2e6578616d706c652e636f6d300d820b6578616d706c652e636f6d300a8708c0a80000ffff0000300a870801000000ff0000003011810f666f6f406578616d706c652e636f6d300a86082e6261722e636f6d300986076261722e636f6da16f3011820f6261722e6578616d706c652e636f6d3022872020010db8000000000000000000000000ffffffffffff00000000000000000000300e810c2e6578616d706c652e636f6d300d810b6578616d706c652e636f6d300b86092e626172322e636f6d300a8608626172322e636f6d30570603551d1f0450304e3025a023a021861f687474703a2f2f63726c312e6578616d706c652e636f6d2f6361312e63726c3025a023a021861f687474703a2f2f63726c322e6578616d706c652e636f6d2f6361312e63726c301606032a0304040f657874726120657874656e73696f6e300d0603551d0e040604040403020130050603290000038202940039434807a0ef1e5749df19521788e2e2e38158b0c3459ff89f743c0e7241c196e8746ffa856096bf1c72ff93b4b71e9899d49ea53b6371092102ecca18f65d6b49a0831f908be9e86ce54155d47e323fedc45963ebf2a2840d59e7b1bbc1890f8655d88feab37198d3a094207f92d75e7bae3975d516bc4f480e839a97c11a048f0899e05f681619a44af2a9c7018a611023b143c7e951d4fe762b587edb5270585175b05c720ec7a2c127491f942dc3c2ac7e46f77f28d3210f7138969bd63df2e6fd362ed4f54e59bb761933c11ab5a3de0e193aa156520560d6543183586a59c471a6f5f229af840a7be7d23a1728239081c039586a6acca1f2bd15c4c209c5dd448d5c55ccc22234156afca3ee949b491f94f32affd4cf3afb641be65e57047324af173f769c7ee5020941c6b8b1afec2f20d769a65f2ce7d39e8440f99fe62caa6a63b0d3f065d756e0d3496e7ad2f87924a57d8c4ab2984931543a4ccf950920990197aae90d1d8e8087f51833e3dbf5d075b734451973f87ec92d051d6b42a28d57602c96850f4660a61987d9f89025234d5fcf06d7f3e21c88c159cb99f6c1205b98e6482076668893519215f195372c73107ad277634ccb2e755986f9bd3ace4591bf6f63afc590d7a764e98350bd1e1c8b009c95aaa426f6be4e790d8d34d74bd292a756fdeab0ac3eebd28e6e66cbd4a9365388d5c64eb667d39f69a492661ccc3105f4bdd51d5b4bfc8e9c5ed64d494b3a072628ca4514074914a7496b35780606e4b778a45066e18a4b09a11a996bbdba74c5c474b47b5f2e61853035820d4ab0e56edc52d749f2df94278d1c53d2066d125331c35a8b2a48d8cea8f10dab06fed22b8c4779a382109bb5da4fb496acf4becf48ec926c16d8d25498f38adfc7486b29ee7b0806ce6ab62a0b44")

var testEd25519Certificate = fromHex("3082012e3081e1a00302010202100f431c425793941de987e4f1ad15005d300506032b657030123110300e060355040a130741636d6520436f301e170d3139303531363231333830315a170d3230303531353231333830315a30123110300e060355040a130741636d6520436f302a300506032b65700321003fe2152ee6e3ef3f4e854a7577a3649eede0bf842ccc92268ffa6f3483aaec8fa34d304b300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff0402300030160603551d11040f300d820b6578616d706c652e636f6d300506032b65700341006344ed9cc4be5324539fd2108d9fe82108909539e50dc155ff2c16b71dfcab7d4dd4e09313d0a942e0b66bfe5d6748d79f50bc6ccd4b03837cf20858cdaccf0c")

var testFalcon512Certificate = fromHex("3082098d308206eda0030201020201ff30050603290000305031153013060355040a130c546573742041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d310f300d060355042a1306476f70686572310b3009060355040613024e4c301e170d3730303130313030313634305a170d3730303130323033343634305a305031153013060355040a130c546573742041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d310f300d060355042a1306476f70686572310b3009060355040613024e4c3082038d3005060329000003820382000919208ee1a8eb5b147c012b2dd94b3ddd20871b99e758386941c6439e7ae81c66cad7be8f8c7f1a13c7743c1ae093be524577151ccbb9db35b6555b037286a96e6a7c5943a9f2b8a95de06b1c9b2146af06b499253470cef092e45d306af3636adae87fbd7b40a525bb7ae48260358602a44d42340cc8d731061383ed92a025ea9d11a11d4b59d510ea5100b38bbe4a3335ebda6cc041728a090db88d6b380844df0c6e7ca70651d98e1ee7f2e98d1431396345466927b8fdbd15bf2f59105080a41395020db1c86a31854f9afc0ca37c9ea611ca71e6ec11b74b60b765b7e9ecb9f6b78aa2202990f1d776eb2b7a81fc9541a88a24281437dafa0500b90c11f7e1ed65abc86f35b8cee547486dd4a39c8189a43d50caaf1728e9aeeb87e769acf536758354501282bab547a5b06ec67ef7c50501bc054798a98b5f5c6273f6766b3f3490fda65e0cab9b3ac5281045ea2db23a00c1dce093c6ccc16b91f16011e2544355918470e07b0b9e8c37f8faf7b541b2490a20c92f42166c31b02074dd0c90956425a18a9493ee507240cf32bfde77c79b837e68b93ba544115874baff0b2b14214d2462aa6d9b5566a0453bcb689b818a27468b2e4280d5e3d91d5d8ca97853ab5708ea39f15d689b9b3bbac96b69099fff0ad1dae9f014e2783c2b370f29458c2e6a9aa3d03c3756f98621a6aa72616fba6d95c316f67cd49f43927e8e6608a827fdbff9b5a820e7be219e7ef15d06ccab80cbf06745d91d14ac546e9306855a799a7e0b145caeaa97fe833d53956b3be4aa18572a048042ea3d3f94665a23259c857a9043a9612b4ee0ad76c0cd9ebc14e5a905a9e34da5a702c31b98909dfeca6d1602aeb4c276decdc973ea69e0b1d14abd1296837e49442bf81e9a006b52437d261a320e0238583682b5d17c8f547f9a1050be7a6d45739068116f35ae9302d6533ad8d2c4a0089084599c07f5ad9ea0cd792be51c0d2d2955da05a782a4d6246492e4b3b992870b8e0563610217424ba9fd11dc64e6495bdc4b50e536b52aaa8ded8f20f3e6d97addbf62862a7b9101ae4411afb74ba9c6a01ae0ed77bdc8a08a9612b73ad1176e5e410000bdf6ccc3d2957608a45613f82512aaf44b2c7e6bddedd9e05d728afe1fe8c450725ce9f90921019085044115d015731a8daa99a7edcc6ea91312189df178858903e456c16d7d4ce71392d851eca6b3928a410116a7fa27406367aab707a613a939bef497fdea844f42ee97b11d85a382028530820281300e0603551d0f0101ff04040302020430260603551d25041f301d06082b0601050507030206082b0601050507030106022a030603810b01300f0603551d130101ff040530030101ff305f06082b0601050507010104533051302306082b060105050730018617687474703a2f2f6f6373702e6578616d706c652e636f6d302a06082b06010505073002861e687474703a2f2f6372742e6578616d706c652e636f6d2f6361312e63727430620603551d11045b30598210746573742e6578616d706c652e636f6d8111676f7068657240676f6c616e672e6f726787047f000001871020014860000020010000000000000068861a68747470733a2f2f666f6f2e636f6d2f776962626c6523666f6f300f0603551d2004083006300406022a033081df0603551d1e0481d73081d4a061300e820c2e6578616d706c652e636f6d300d820b6578616d706c652e636f6d300a8708c0a80000ffff0000300a870801000000ff0000003011810f666f6f406578616d706c652e636f6d300a86082e6261722e636f6d300986076261722e636f6da16f3011820f6261722e6578616d706c652e636f6d3022872020010db8000000000000000000000000ffffffffffff00000000000000000000300e810c2e6578616d706c652e636f6d300d810b6578616d706c652e636f6d300b86092e626172322e636f6d300a8608626172322e636f6d30570603551d1f0450304e3025a023a021861f687474703a2f2f63726c312e6578616d706c652e636f6d2f6361312e63726c3025a023a021861f687474703a2f2f63726c322e6578616d706c652e636f6d2f6361312e63726c301606032a0304040f657874726120657874656e73696f6e300d0603551d0e0406040404030201300506032900000382029100396ad85fe31596e8b5b49f51ae3dcca3d51882bc8577af426b139720f04ba51ff3f8e404fa9f7087a7c24a14d863127e70eaf746452affb1ad8ca188ba54aed25c6e8c95262d8ef9dcab103a77369050f086e21711215b895ac5fe9d305125ed055fded26d94fddb324d4314b35e592d641ab3433588316c54f90e7a3b6f8c34c4babb9b816425f986b5bf340cd8ad30c3d71e29d60927e5912750c55bc47fb6ca1fdf039a52e930a71e0aa86612f85a1052d0e6c3c09d9656116699c8baeb099d512b17f62887dbed7b74459035ad2e5f21dbef7116c8abb7a41e3962813585fae2088fc7f5b1663d993c3a0c4b279967622448246e21a2dbf16a973db55563404b1355ebab50b53ca77a8be5974811dcb7377338b1d598926c47eb0ee7ad363610d83d1d84f3e9f2f16ec4fef48c26b9eb72facfe27fbe2d2d3a91b9e22aad5a29bcd2d41a6a9682a0913b0effb58213bbdb8581519d9533e16420c93387af375ce822244c86e97b4e14a938c3c738e5049ad6b9fad254dca95917c5924918673d5955d4ae47cdcfafaff94270cbd91b02596abc498de6572551604b67023c9c714f7487e4bd6219a8476f00f6ab579870df3cf008e240b82fe5e3dcbce44d1c3d8faec30cecade8843bb514ff0cbfef7af2b94c1a3f1028e9b92bf768e1dbca526178a6e47b6b7ea9a6dedae528ba1379fbb0c487a098e550c635d6dc336c5996c46ca58b4af5405e4bd9ea5072f43a1b59d4d70d24ff3f104f1da1f5dff3282ff2c53baba628bdcd3b8fb49d68e68bc4e6912cc2d853d8e75723bc87af1ebb766636f1b27e1df0aee4238c5ccbcdeccd3fcd8ac3e2eb3b1cf921552d7898fa1e4db69ad5887694dc1e9de9b6bfd81109b654da16a0442e505c1c91ce8c7c765034232c7baeb7ebf64a6cf960e670")

var testSNICertificate = fromHex("0441883421114c81480804c430820237308201a0a003020102020900e8f09d3fe25beaa6300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a3023310b3009060355040a1302476f311430120603550403130b736e69746573742e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d70203010001a3773075300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff0402300030190603551d0e041204109f91161f43433e49a6de6db680d79f60301b0603551d230414301280104813494d137e1631bba301d5acab6e7b300d06092a864886f70d01010b0500038181007beeecff0230dbb2e7a334af65430b7116e09f327c3bbf918107fc9c66cb497493207ae9b4dbb045cb63d605ec1b5dd485bb69124d68fa298dc776699b47632fd6d73cab57042acb26f083c4087459bc5a3bb3ca4d878d7fe31016b7bc9a627438666566e3389bfaeebe6becc9a0093ceed18d0f9ac79d56f3a73f18188988ed")

var testP256Certificate = fromHex("308201693082010ea00302010202105012dc24e1124ade4f3e153326ff27bf300a06082a8648ce3d04030230123110300e060355040a130741636d6520436f301e170d3137303533313232343934375a170d3138303533313232343934375a30123110300e060355040a130741636d6520436f3059301306072a8648ce3d020106082a8648ce3d03010703420004c02c61c9b16283bbcc14956d886d79b358aa614596975f78cece787146abf74c2d5dc578c0992b4f3c631373479ebf3892efe53d21c4f4f1cc9a11c3536b7f75a3463044300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000300f0603551d1104083006820474657374300a06082a8648ce3d0403020349003046022100963712d6226c7b2bef41512d47e1434131aaca3ba585d666c924df71ac0448b3022100f4d05c725064741aef125f243cdbccaa2a5d485927831f221c43023bd5ae471a")

var testRSAPrivateKey, _ = x509.ParsePKCS1PrivateKey(fromHex("3082025b02010002818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d702030100010281800b07fbcf48b50f1388db34b016298b8217f2092a7c9a04f77db6775a3d1279b62ee9951f7e371e9de33f015aea80660760b3951dc589a9f925ed7de13e8f520e1ccbc7498ce78e7fab6d59582c2386cc07ed688212a576ff37833bd5943483b5554d15a0b9b4010ed9bf09f207e7e9805f649240ed6c1256ed75ab7cd56d9671024100fded810da442775f5923debae4ac758390a032a16598d62f059bb2e781a9c2f41bfa015c209f966513fe3bf5a58717cbdb385100de914f88d649b7d15309fa49024100dd10978c623463a1802c52f012cfa72ff5d901f25a2292446552c2568b1840e49a312e127217c2186615aae4fb6602a4f6ebf3f3d160f3b3ad04c592f65ae41f02400c69062ca781841a09de41ed7a6d9f54adc5d693a2c6847949d9e1358555c9ac6a8d9e71653ac77beb2d3abaf7bb1183aa14278956575dbebf525d0482fd72d90240560fe1900ba36dae3022115fd952f2399fb28e2975a1c3e3d0b679660bdcb356cc189d611cfdd6d87cd5aea45aa30a2082e8b51e94c2f3dd5d5c6036a8a615ed0240143993d80ece56f877cb80048335701eb0e608cc0c1ca8c2227b52edf8f1ac99c562f2541b5ce81f0515af1c5b4770dba53383964b4b725ff46fdec3d08907df"))

var testECDSAPrivateKey, _ = x509.ParseECPrivateKey(fromHex("3081dc0201010442019883e909ad0ac9ea3d33f9eae661f1785206970f8ca9a91672f1eedca7a8ef12bd6561bb246dda5df4b4d5e7e3a92649bc5d83a0bf92972e00e62067d0c7bd99d7a00706052b81040023a18189038186000400c4a1edbe98f90b4873367ec316561122f23d53c33b4d213dcd6b75e6f6b0dc9adf26c1bcb287f072327cb3642f1c90bcea6823107efee325c0483a69e0286dd33700ef0462dd0da09c706283d881d36431aa9e9731bd96b068c09b23de76643f1a5c7fe9120e5858b65f70dd9bd8ead5d7f5d5ccb9b69f30665b669a20e227e5bffe3b"))

var testP256PrivateKey, _ = x509.ParseECPrivateKey(fromHex("30770201010420012f3b52bc54c36ba3577ad45034e2e8efe1e6999851284cb848725cfe029991a00a06082a8648ce3d030107a14403420004c02c61c9b16283bbcc14956d886d79b358aa614596975f78cece787146abf74c2d5dc578c0992b4f3c631373479ebf3892efe53d21c4f4f1cc9a11c3536b7f75"))

var testEd25519PrivateKey = ed25519.PrivateKey(fromHex("3a884965e76b3f55e5faf9615458a92354894234de3ec9f684d46d55cebf3dc63fe2152ee6e3ef3f4e854a7577a3649eede0bf842ccc92268ffa6f3483aaec8f"))

var testFalcon512PrivateKey = falcon512.PrivateKey{
	PublicKey: falcon512.PublicKey{
		Pk: fromHex("0919208ee1a8eb5b147c012b2dd94b3ddd20871b99e758386941c6439e7ae81c66cad7be8f8c7f1a13c7743c1ae093be524577151ccbb9db35b6555b037286a96e6a7c5943a9f2b8a95de06b1c9b2146af06b499253470cef092e45d306af3636adae87fbd7b40a525bb7ae48260358602a44d42340cc8d731061383ed92a025ea9d11a11d4b59d510ea5100b38bbe4a3335ebda6cc041728a090db88d6b380844df0c6e7ca70651d98e1ee7f2e98d1431396345466927b8fdbd15bf2f59105080a41395020db1c86a31854f9afc0ca37c9ea611ca71e6ec11b74b60b765b7e9ecb9f6b78aa2202990f1d776eb2b7a81fc9541a88a24281437dafa0500b90c11f7e1ed65abc86f35b8cee547486dd4a39c8189a43d50caaf1728e9aeeb87e769acf536758354501282bab547a5b06ec67ef7c50501bc054798a98b5f5c6273f6766b3f3490fda65e0cab9b3ac5281045ea2db23a00c1dce093c6ccc16b91f16011e2544355918470e07b0b9e8c37f8faf7b541b2490a20c92f42166c31b02074dd0c90956425a18a9493ee507240cf32bfde77c79b837e68b93ba544115874baff0b2b14214d2462aa6d9b5566a0453bcb689b818a27468b2e4280d5e3d91d5d8ca97853ab5708ea39f15d689b9b3bbac96b69099fff0ad1dae9f014e2783c2b370f29458c2e6a9aa3d03c3756f98621a6aa72616fba6d95c316f67cd49f43927e8e6608a827fdbff9b5a820e7be219e7ef15d06ccab80cbf06745d91d14ac546e9306855a799a7e0b145caeaa97fe833d53956b3be4aa18572a048042ea3d3f94665a23259c857a9043a9612b4ee0ad76c0cd9ebc14e5a905a9e34da5a702c31b98909dfeca6d1602aeb4c276decdc973ea69e0b1d14abd1296837e49442bf81e9a006b52437d261a320e0238583682b5d17c8f547f9a1050be7a6d45739068116f35ae9302d6533ad8d2c4a0089084599c07f5ad9ea0cd792be51c0d2d2955da05a782a4d6246492e4b3b992870b8e0563610217424ba9fd11dc64e6495bdc4b50e536b52aaa8ded8f20f3e6d97addbf62862a7b9101ae4411afb74ba9c6a01ae0ed77bdc8a08a9612b73ad1176e5e410000bdf6ccc3d2957608a45613f82512aaf44b2c7e6bddedd9e05d728afe1fe8c450725ce9f90921019085044115d015731a8daa99a7edcc6ea91312189df178858903e456c16d7d4ce71392d851eca6b3928a410116a7fa27406367aab707a613a939bef497fdea844f42ee97b11d85"),
	},
	Sk: fromHex("59181fbcf42083fc1008ffd17f13ef43efc0b8145f44045ffe004001142f85f00e44fbe101f81e85003f7ce7f0bf0030fdf7cebc0c1e480410ba07aec7084f80e00002ffa200fc00430fe23c0bc17b105fc4f85f02efef0110c142ef8ec107b045fc40bff3c144103087082041f811c3f49ffe081eff0c303f101044f8408207b1b9002fbde42f42f3a100ffa0c203d103042fb82f8effffeffde81f7914503efc1e38040e45f8503e0810bef82002f081c41490fef4018a13ef4307f23e07debef00042040f84fbce88fbf140e41fc304513cfc3ec0f01f02ec70fef86e41ec3fc20420beec90c01001830b517eebe0fbf87e3e23e0830c1fc808303eff9081f3d13cec1e41f82f0807d03d07ef8707803e00910afc807f08413c141002ffffc203fdc9ffbf07dfcfc1f7c0be07f0020bdfc20baefa13ff8803f104f42102040fc2fbc03c03b1bcd40181f810bff7d0bffbfe01ec1003fbe0bc0c30410bc043103040fbf03cf4703f0fb1bdefc08200c0bbfbe0ff135f840430800011410bbfbf03efc6f0303df3dfff03f087e3b08707e1030c0e81103042f80143201043e79ffff7cec00fe082fc1002ebdebeffe0c3f811bdf03fbff43fc4042ffbe82f8403c07e0fcf08083e461ffffe043148f0013e005f44102046fbfe7f182fbef790fa046efdf032c1e44082e83f8417dffc07efbd1420ffffff44044ec317f0c30c6fc3080f88fc6240f7d07f0fe081081202f40ffb104140d8c040002f7efc10c71401fb0021811bf142f3e23cffd0be102d440820ff07ff3e0bffbf185042e83dc40bef430c0ff817ff00f3e13bec1fc1fbde87104e021050830baffa00207903dffc0021ff13efc203ffc207f1f9047f790bfe4a182f3dec5f7d0770001bd001f3df3ee7c002fc70c804213b03a0ba1b913ef370440800052befc1ff927e0bf04307e1bc043047ec600affc0fbf7ff4207f03efbc142101f4108310afff17f083f821c310307d1baf39f45fbefc0004ffe1bfe44ec5ebd040ffde420ffec5e810bbe3d0ba0bf13e084fc0fc107ef3e1450c208200ef42f82f8610304917d080145ec1fde1df813fdf04111ec010af20b2cd133daee090b13ebf8f9d50de1030b06261910d92415ed04f8bef1d823fc0ce42af3e3030528fa28e107f4fbe91f140c3125f91500e5eb02f1f60f1af5f3091dd90618dcfc2515e8140e02df091df901ea41e408e10aee000ae2f405101525fb05e7dbeaeee8f2140917ecfaf9e8dcef141ae4d10106eef0060be02503f7f9ea070f26e00c2d032f0f150b1428fc0722e32cef1f07e10f0fe3fd07f518fdfc111212dadf06eadf1ac1f7f90816f40103121115140317090f03ea111e03040b0af5ef0a3516f529db24f51ee3e7dad8f9fef31d15c8db36e3c315e6d8ee0c0a16ed00f42bf2290e24141104eb1809f42705f20315d641030d0a0fe5f411f0edf0c00d25ddf1fbfdef031100fcf4f21dfa20082f0cf3f8f60008fb0f093043f90ef4fa1312f71bfd11f8e3020ede15f51ee000f105faeef6ede7e31cf6d908ed16de0d09f6f315eb2320e81f00fcdb160af5e119f02c0118f5e4ecff05da4c10f0111305d6e5f43219ef2cedfce8f7ffdb03120cfb0ffd020bff22ebe11f051902051bf001ebff1d072b0c080eee2bf306fe153601f43adf0bfcf3fd05da1b2bebdd14f6d7291deb2f22ffff10e905e9f5de1ce6f225df061fe6d800e5eee319062dfef8f0d9eaf9e501fd003611ee1b041c09ef230307eb0d2315eaf7e4dde9f1df0e2e0efcd91ad6d3fe260eed0e1927"),
}

const clientCertificatePEM = `
-----BEGIN CERTIFICATE-----
MIIB7zCCAVigAwIBAgIQXBnBiWWDVW/cC8m5k5/pvDANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMB4XDTE2MDgxNzIxNTIzMVoXDTE3MDgxNzIxNTIz
MVowEjEQMA4GA1UEChMHQWNtZSBDbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAum+qhr3Pv5/y71yUYHhv6BPy0ZZvzdkybiI3zkH5yl0prOEn2mGi7oHLEMff
NFiVhuk9GeZcJ3NgyI14AvQdpJgJoxlwaTwlYmYqqyIjxXuFOE8uCXMyp70+m63K
hAfmDzr/d8WdQYUAirab7rCkPy1MTOZCPrtRyN1IVPQMjkcCAwEAAaNGMEQwDgYD
VR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAw
DwYDVR0RBAgwBocEfwAAATANBgkqhkiG9w0BAQsFAAOBgQBGq0Si+yhU+Fpn+GKU
8ZqyGJ7ysd4dfm92lam6512oFmyc9wnTN+RLKzZ8Aa1B0jLYw9KT+RBrjpW5LBeK
o0RIvFkTgxYEiKSBXCUNmAysEbEoVr4dzWFihAm/1oDGRY2CLLTYg5vbySK3KhIR
e/oCO8HJ/+rJnahJ05XX1Q7lNQ==
-----END CERTIFICATE-----`

var clientKeyPEM = testingKey(`
-----BEGIN RSA TESTING KEY-----
MIICXQIBAAKBgQC6b6qGvc+/n/LvXJRgeG/oE/LRlm/N2TJuIjfOQfnKXSms4Sfa
YaLugcsQx980WJWG6T0Z5lwnc2DIjXgC9B2kmAmjGXBpPCViZiqrIiPFe4U4Ty4J
czKnvT6brcqEB+YPOv93xZ1BhQCKtpvusKQ/LUxM5kI+u1HI3UhU9AyORwIDAQAB
AoGAEJZ03q4uuMb7b26WSQsOMeDsftdatT747LGgs3pNRkMJvTb/O7/qJjxoG+Mc
qeSj0TAZXp+PXXc3ikCECAc+R8rVMfWdmp903XgO/qYtmZGCorxAHEmR80SrfMXv
PJnznLQWc8U9nphQErR+tTESg7xWEzmFcPKwnZd1xg8ERYkCQQDTGtrFczlB2b/Z
9TjNMqUlMnTLIk/a/rPE2fLLmAYhK5sHnJdvDURaH2mF4nso0EGtENnTsh6LATnY
dkrxXGm9AkEA4hXHG2q3MnhgK1Z5hjv+Fnqd+8bcbII9WW4flFs15EKoMgS1w/PJ
zbsySaSy5IVS8XeShmT9+3lrleed4sy+UwJBAJOOAbxhfXP5r4+5R6ql66jES75w
jUCVJzJA5ORJrn8g64u2eGK28z/LFQbv9wXgCwfc72R468BdawFSLa/m2EECQGbZ
rWiFla26IVXV0xcD98VWJsTBZMlgPnSOqoMdM1kSEd4fUmlAYI/dFzV1XYSkOmVr
FhdZnklmpVDeu27P4c0CQQCuCOup0FlJSBpWY1TTfun/KMBkBatMz0VMA3d7FKIU
csPezl677Yjo8u1r/KzeI6zLg87Z8E6r6ZWNc9wBSZK6
-----END RSA TESTING KEY-----`)

const clientECDSACertificatePEM = `
-----BEGIN CERTIFICATE-----
MIIB/DCCAV4CCQCaMIRsJjXZFzAJBgcqhkjOPQQBMEUxCzAJBgNVBAYTAkFVMRMw
EQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0
eSBMdGQwHhcNMTIxMTE0MTMyNTUzWhcNMjIxMTEyMTMyNTUzWjBBMQswCQYDVQQG
EwJBVTEMMAoGA1UECBMDTlNXMRAwDgYDVQQHEwdQeXJtb250MRIwEAYDVQQDEwlK
b2VsIFNpbmcwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABACVjJF1FMBexFe01MNv
ja5oHt1vzobhfm6ySD6B5U7ixohLZNz1MLvT/2XMW/TdtWo+PtAd3kfDdq0Z9kUs
jLzYHQFMH3CQRnZIi4+DzEpcj0B22uCJ7B0rxE4wdihBsmKo+1vx+U56jb0JuK7q
ixgnTy5w/hOWusPTQBbNZU6sER7m8TAJBgcqhkjOPQQBA4GMADCBiAJCAOAUxGBg
C3JosDJdYUoCdFzCgbkWqD8pyDbHgf9stlvZcPE4O1BIKJTLCRpS8V3ujfK58PDa
2RU6+b0DeoeiIzXsAkIBo9SKeDUcSpoj0gq+KxAxnZxfvuiRs9oa9V2jI/Umi0Vw
jWVim34BmT0Y9hCaOGGbLlfk+syxis7iI6CH8OFnUes=
-----END CERTIFICATE-----`

var clientECDSAKeyPEM = testingKey(`
-----BEGIN EC PARAMETERS-----
BgUrgQQAIw==
-----END EC PARAMETERS-----
-----BEGIN EC TESTING KEY-----
MIHcAgEBBEIBkJN9X4IqZIguiEVKMqeBUP5xtRsEv4HJEtOpOGLELwO53SD78Ew8
k+wLWoqizS3NpQyMtrU8JFdWfj+C57UNkOugBwYFK4EEACOhgYkDgYYABACVjJF1
FMBexFe01MNvja5oHt1vzobhfm6ySD6B5U7ixohLZNz1MLvT/2XMW/TdtWo+PtAd
3kfDdq0Z9kUsjLzYHQFMH3CQRnZIi4+DzEpcj0B22uCJ7B0rxE4wdihBsmKo+1vx
+U56jb0JuK7qixgnTy5w/hOWusPTQBbNZU6sER7m8Q==
-----END EC TESTING KEY-----`)

const clientEd25519CertificatePEM = `
-----BEGIN CERTIFICATE-----
MIIBLjCB4aADAgECAhAX0YGTviqMISAQJRXoNCNPMAUGAytlcDASMRAwDgYDVQQK
EwdBY21lIENvMB4XDTE5MDUxNjIxNTQyNloXDTIwMDUxNTIxNTQyNlowEjEQMA4G
A1UEChMHQWNtZSBDbzAqMAUGAytlcAMhAAvgtWC14nkwPb7jHuBQsQTIbcd4bGkv
xRStmmNveRKRo00wSzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUH
AwIwDAYDVR0TAQH/BAIwADAWBgNVHREEDzANggtleGFtcGxlLmNvbTAFBgMrZXAD
QQD8GRcqlKUx+inILn9boF2KTjRAOdazENwZ/qAicbP1j6FYDc308YUkv+Y9FN/f
7Q7hF9gRomDQijcjKsJGqjoI
-----END CERTIFICATE-----`

var clientEd25519KeyPEM = testingKey(`
-----BEGIN TESTING KEY-----
MC4CAQAwBQYDK2VwBCIEINifzf07d9qx3d44e0FSbV4mC/xQxT644RRbpgNpin7I
-----END TESTING KEY-----`)

const clientFalcon512CertificatePEM = `
-----BEGIN CERTIFICATE-----
MIIJjTCCBu2gAwIBAgIB/zAFBgMpAAAwUDEVMBMGA1UEChMMVGVzdCBBY21lIENv
MRkwFwYDVQQDExB0ZXN0LmV4YW1wbGUuY29tMQ8wDQYDVQQqEwZHb3BoZXIxCzAJ
BgNVBAYTAk5MMB4XDTcwMDEwMTAwMTY0MFoXDTcwMDEwMjAzNDY0MFowUDEVMBMG
A1UEChMMVGVzdCBBY21lIENvMRkwFwYDVQQDExB0ZXN0LmV4YW1wbGUuY29tMQ8w
DQYDVQQqEwZHb3BoZXIxCzAJBgNVBAYTAk5MMIIDjTAFBgMpAAADggOCAAkZII7h
qOtbFHwBKy3ZSz3dIIcbmedYOGlBxkOeeugcZsrXvo+MfxoTx3Q8GuCTvlJFdxUc
y7nbNbZVWwNyhqluanxZQ6nyuKld4GscmyFGrwa0mSU0cM7wkuRdMGrzY2ra6H+9
e0ClJbt65IJgNYYCpE1CNAzI1zEGE4PtkqAl6p0RoR1LWdUQ6lEAs4u+SjM169ps
wEFyigkNuI1rOAhE3wxufKcGUdmOHufy6Y0UMTljRUZpJ7j9vRW/L1kQUICkE5UC
DbHIajGFT5r8DKN8nqYRynHm7BG3S2C3Zbfp7Ln2t4qiICmQ8dd26yt6gfyVQaiK
JCgUN9r6BQC5DBH34e1lq8hvNbjO5UdIbdSjnIGJpD1Qyq8XKOmu64fnaaz1NnWD
VFASgrq1R6WwbsZ+98UFAbwFR5ipi19cYnP2dms/NJD9pl4Mq5s6xSgQReotsjoA
wdzgk8bMwWuR8WAR4lRDVZGEcOB7C56MN/j697VBskkKIMkvQhZsMbAgdN0MkJVk
JaGKlJPuUHJAzzK/3nfHm4N+aLk7pUQRWHS6/wsrFCFNJGKqbZtVZqBFO8tom4GK
J0aLLkKA1ePZHV2MqXhTq1cI6jnxXWibmzu6yWtpCZ//CtHa6fAU4ng8KzcPKUWM
Lmqao9A8N1b5hiGmqnJhb7ptlcMW9nzUn0OSfo5mCKgn/b/5tagg574hnn7xXQbM
q4DL8GdF2R0UrFRukwaFWnmafgsUXK6ql/6DPVOVazvkqhhXKgSAQuo9P5RmWiMl
nIV6kEOpYStO4K12wM2evBTlqQWp402lpwLDG5iQnf7KbRYCrrTCdt7NyXPqaeCx
0Uq9EpaDfklEK/gemgBrUkN9JhoyDgI4WDaCtdF8j1R/mhBQvnptRXOQaBFvNa6T
AtZTOtjSxKAIkIRZnAf1rZ6gzXkr5RwNLSlV2gWngqTWJGSS5LO5kocLjgVjYQIX
Qkup/RHcZOZJW9xLUOU2tSqqje2PIPPm2Xrdv2KGKnuRAa5EEa+3S6nGoBrg7Xe9
yKCKlhK3OtEXbl5BAAC99szD0pV2CKRWE/glEqr0Syx+a93t2eBdcor+H+jEUHJc
6fkJIQGQhQRBFdAVcxqNqpmn7cxuqRMSGJ3xeIWJA+RWwW19TOcTkthR7KazkopB
ARan+idAY2eqtwemE6k5vvSX/eqET0Lul7EdhaOCAoUwggKBMA4GA1UdDwEB/wQE
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
BAQDAgEwBQYDKQAAA4ICkQA5athf4xWW6LW0n1GuPcyj1RiCvIV3r0JrE5cg8Eul
H/P45AT6n3CHp8JKFNhjEn5w6vdGRSr/sa2MoYi6VK7SXG6MlSYtjvncqxA6dzaQ
UPCG4hcRIVuJWsX+nTBRJe0FX97SbZT92zJNQxSzXlktZBqzQzWIMWxU+Q56O2+M
NMS6u5uBZCX5hrW/NAzYrTDD1x4p1gkn5ZEnUMVbxH+2yh/fA5pS6TCnHgqoZhL4
WhBS0ObDwJ2WVhFmmci66wmdUSsX9iiH2+17dEWQNa0uXyHb73EWyKu3pB45YoE1
hfriCI/H9bFmPZk8OgxLJ5lnYiRIJG4hotvxapc9tVVjQEsTVeurULU8p3qL5ZdI
Edy3N3M4sdWYkmxH6w7nrTY2ENg9HYTz6fLxbsT+9Iwmuety+s/if74tLTqRueIq
rVopvNLUGmqWgqCROw7/tYITu9uFgVGdlTPhZCDJM4evN1zoIiRMhul7ThSpOMPH
OOUEmta5+tJU3KlZF8WSSRhnPVlV1K5Hzc+vr/lCcMvZGwJZarxJjeZXJVFgS2cC
PJxxT3SH5L1iGahHbwD2q1eYcN888AjiQLgv5ePcvORNHD2PrsMM7K3ohDu1FP8M
v+968rlMGj8QKOm5K/do4dvKUmF4puR7a36ppt7a5Si6E3n7sMSHoJjlUMY11twz
bFmWxGyli0r1QF5L2epQcvQ6G1nU1w0k/z8QTx2h9d/zKC/yxTurpii9zTuPtJ1o
5ovE5pEswthT2OdXI7yHrx67dmY28bJ+HfCu5COMXMvN7M0/zYrD4us7HPkhVS14
mPoeTbaa1Yh2lNwenem2v9gRCbZU2hagRC5QXByRzox8dlA0Iyx7rrfr9kps+WDm
cA==
-----END CERTIFICATE-----`

var clientFalcon512KeyPEM = `
-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----`

func TestCert(t *testing.T) {
	//testRSACertificate
	//cert, _ := x509.ParseCertificate(testRSACertificate)
	cert, _ := x509.ParseCertificate(testFalcon512Certificate)
	fmt.Println(cert)
}

func genPem(atype string, msg []byte) {
	block := pem.Block{
		Type:  atype,
		Bytes: msg,
	}

	pem.Encode(os.Stdout, &block)
}

// 生成falcon512 cert, publicKey, secretKey hex string
func TestGenFalcon512Cert(t *testing.T) {
	random := rand.Reader

	pqcPriv, err := falcon512.GenerateKey()
	fmt.Println(hex.EncodeToString(pqcPriv.PublicKey.Pk))
	// 09b3b0a1a15202c37fc27e09e1a81b1afaef21ddca04a3791a9504d0fe0496a1095d8ddd291dc963b06f1702feb28237590906fd88a75dd3355a154be3f389c94e16dea582afc37be08af98516fb1b8650fb3461fa9c4a04f7d5a25a9be81fb793a0555f21f711358fb0099242b36b1e8fae6c2c70d813bb6ca09449075cb21396e3b40c250578b60afb1980615774b5a49ba12d4771e4e4d0a86aae5a43f4654def8bc4523523d258b4fe9696f499946a7c53e62e1bc43eee0361d229351b4205b4f19a474fc691d716ab91116c5138b6090faaaad705a9c34b8179fd644c2afd110080216683456784afd9ff10398cea0702a2c6325989bd03bdc2ad57f17179c69e8e905dcbd0815d5dad0887fb054cbb8080f999a2d8cc0c986f72c043a29e95c9c39dc6b69568fdf9e90d3c1c8456372a8b6725cac6579f98c86d0d9a6ace203c92248967be180918d601db0d1eae3d75eed9901c57adbeb6e96d1a290170ed301fcbb4b02430011680ef2ba20ef0be5b8a1086ef26addfde55599ca7c9cd347495acf2708e618d1c1b301ea56721d88f529ad8ce4b1ded17e4abd96f9df8a0fdaa600a3661e53ad5f240b2d1556288c201d8a382f8cd82370c0942aeaf971860a8c9f4a71a9c991903dd949fb275920930e5c2bed62216d646efa39230811c6014b0ee054903845a2705a88a390d284490bd94c748df5a1e46c7cd5727382eed970544e197ac4bc02d4085054994e85f6313569de018c0579446761bc3a3164e7cb06c7928d8cf2094a656cb2844a0d896a70b86eb5dde18a767d6c863dc4f5b56c00204d9d7264e979e2fa1467030411685fa0cb52502ee03e1517a53eb4e8e2157fa2b04d8a4d402d1992f958a957ca21f017660f14e904950c47179d06a392f660db5f1e95e26269a05f603fa6c1500da56265b8e2e5246d4f44120e555545f16b0d41abbfce64756e4016d953103134d1a334009d12b1b0f64a6bce89adf589e89b793b601551b74e5ba8566bb2e95b1551597577c20e9f1afef9021e6ea34ae56619dd185c83ec65669c29aab8564f00c85f51bf614079e72a8315ed6b9b7d8a910898c6e391886427e4984792ef0f0df2cea453cb90040dec020b44c97659cda5681f5092bcce5bbfdd0bb28484262a1d5d3f456259e0095c1c1e696280117b7f3558f8a98b93b32ea9748648922b40a3e2fea0a02c327e4ba49c477e8a1fd6b52a6f79464671d0465ab591bf995fa548222df60618ac30550cc59
	fmt.Println(hex.EncodeToString(pqcPriv.Sk))
	// 59e00f04dbc13dfc2f4108303d1fc1fe0410fe0baf05efbfbffff002eb9f80186ffd03cf03141041e7c03f17e101148f04ec1efff85fc1f830c1fb6f8ef7a0460c2fc3f4123ffbdfb9fbff41f05fc0041e7a13dffd041f830c114030304013f1430bce7ceff005dfe2070be27f03900203d0fd006ebc13b001d400fffbf085fc51bdf40079ec607d03a100043180e87041288ff7eff03c0bc1000c117d03c0bf1bfffa07c0c0ebb0fd184efc13a03c07a03ff8603bffc08023d085fbffbe13be3bfb8fbfebe0faec60bfeff0000fa0471b507ef7af3c086245f811fd03cf45002041f47f06e3a0ff0baf00ec21b9143083246fc7f830bf0be00713a081044fbde80f81f40f451070c904107f07a08717ffc1e82ffcfbaffdf85139e81ec30c00c1ffd000fbcf40ffe043f7bec103f142f8203debf0760fe0ffefe03cf84ef9fbb13b0bf0bc045081040003fc013ee02f4200103efbd0c00bef3f17ce7ef03fcafbde7fdc303f14003e004ec1fc8fc8f81007fc20fe07f0431010030431c4ebf101042fc41020c4fbefc92460850060b90830820850810821bbfc5eff284e7ee401010fdf02fc20bd1bdff6fff003efd0430810fdf88fc10bcfb4e3f281040103fc3f82081f4208013bebaf7dec2105fbf1400c4fc5005fb703f186fc0dc30c21fb0c10be001f41fb8ec1186e0803dff90fbf80183f87041e7b038ec2dc2d84fc1f84f41f430c3fc0f000c1083141102f02fff00203a0c3f7cf050b1f41ec6e83fc4042f0513ef82f42fbf1bcfbcfbdfc0ebff3c00103ddc2084004fc60861792400fb001049f7f045f850bf03d1430ffdc113b0bfe7f044f031bdffdebf0bb23e0b9ec11c4f800fe0c2f01e410ba0bf0bcf421430fdf78101080102f46ef9f80ffd040f40fc0fc214207e07effd17f109044f3b13f24117f13f001f040fc0060bdfc3f8423f08603dffcffb1f8e0714003f0ffe050f617f0ba03b0440bef8704207dffa07a0fc08217b13d04308304214107b201100ffe0beec2084ffc0b60441bcfb8138185f7bf40046f7e101f88044ffe03d080eba045f3d082fc614903f03e0aeaf90af60b3713edfbe72302dddaffdfe313fffffef30ddd1927f3edcaed07ba09fc0cfaeb03d30ee414ff080ce42de507f110cae50eea070acbbd03f6f4e527e40830132512fddafb083d16dc24ef01ea31c9fb12f5f3eb18040a0321ee0528ed170af4e3d0d511210d03ed14f6f5ee0ef51b1425f7370cf0e9182e0a1e131210edeff0260805fb0ce6c428f8d7f9fcf10c1ef90903293c030203e7301afce1072601281fc71a02e9f80cf202e7fa0cf9fc08080de804ddd2000706d824f9f30808fd07f814eaf50c17e7fbd1db03eb2816f2e21de4fcf8fff106cdf81be31fe60bfe14e0fe0f0bfecd31d509162b2d0713fcea0927eed3f40d12dd2ac9e7d013f019250401fdf6f1181906000f0619fd0402f100e81c112003cc18eb0ff717e6f44211142826dbdef0e711260022def2e8d0161f00dc18f508261414defdeff216081bd632d203071e07e50ac80a44d0f61cf7f12d2b1512ed03f5f2fbf9c42921f8e735f7fe2bfde6e609ea0c0a200ef1ecfcde22f6faf7f8ecfa021201e6fc0b101608df0af8280cef24fef143f6c9f243cafc0ef7181327d3eff7fedfea04ed10f119f3f00210fd3206ebf8e7f4ef13d905170312d3fe072b0af1f0d108f3f6290eece2261dfdfeed14f32205d8fc08dc291c2eeb11cbf0f90208ecf4d9d817e8fd230ffb100bea221efefad61af407041eeb0e0407f7f01103c62319

	pqcPrivBytes, err := x509.MarshalPKCS8PrivateKey(pqcPriv)
	genPem("PRIVATE KEY", pqcPrivBytes)

	if err != nil {
		t.Errorf("failed to generate pqc key: %s", err)
	}

	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")

	commonName := "test.example.com"
	template := x509.Certificate{
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

		SignatureAlgorithm: x509.PureFalcon512,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign,

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
				Id:       []int{2, 5, 29, 14},
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}

	derBytes, err := x509.CreateCertificate(random, &template, &template, &pqcPriv.PublicKey, pqcPriv)
	//
	if err != nil {
		t.Errorf("%s: failed to create certificate: %s", "pqc", err)
	}

	derHexString := hex.EncodeToString(derBytes)
	fmt.Println(derHexString)
	// 30820990308206eda0030201020201ff30050603290000305031153013060355040a130c546573742041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d310f300d060355042a1306476f70686572310b3009060355040613024e4c301e170d3730303130313030313634305a170d3730303130323033343634305a305031153013060355040a130c546573742041636d6520436f3119301706035504031310746573742e6578616d706c652e636f6d310f300d060355042a1306476f70686572310b3009060355040613024e4c3082038d30050603290000038203820009b3b0a1a15202c37fc27e09e1a81b1afaef21ddca04a3791a9504d0fe0496a1095d8ddd291dc963b06f1702feb28237590906fd88a75dd3355a154be3f389c94e16dea582afc37be08af98516fb1b8650fb3461fa9c4a04f7d5a25a9be81fb793a0555f21f711358fb0099242b36b1e8fae6c2c70d813bb6ca09449075cb21396e3b40c250578b60afb1980615774b5a49ba12d4771e4e4d0a86aae5a43f4654def8bc4523523d258b4fe9696f499946a7c53e62e1bc43eee0361d229351b4205b4f19a474fc691d716ab91116c5138b6090faaaad705a9c34b8179fd644c2afd110080216683456784afd9ff10398cea0702a2c6325989bd03bdc2ad57f17179c69e8e905dcbd0815d5dad0887fb054cbb8080f999a2d8cc0c986f72c043a29e95c9c39dc6b69568fdf9e90d3c1c8456372a8b6725cac6579f98c86d0d9a6ace203c92248967be180918d601db0d1eae3d75eed9901c57adbeb6e96d1a290170ed301fcbb4b02430011680ef2ba20ef0be5b8a1086ef26addfde55599ca7c9cd347495acf2708e618d1c1b301ea56721d88f529ad8ce4b1ded17e4abd96f9df8a0fdaa600a3661e53ad5f240b2d1556288c201d8a382f8cd82370c0942aeaf971860a8c9f4a71a9c991903dd949fb275920930e5c2bed62216d646efa39230811c6014b0ee054903845a2705a88a390d284490bd94c748df5a1e46c7cd5727382eed970544e197ac4bc02d4085054994e85f6313569de018c0579446761bc3a3164e7cb06c7928d8cf2094a656cb2844a0d896a70b86eb5dde18a767d6c863dc4f5b56c00204d9d7264e979e2fa1467030411685fa0cb52502ee03e1517a53eb4e8e2157fa2b04d8a4d402d1992f958a957ca21f017660f14e904950c47179d06a392f660db5f1e95e26269a05f603fa6c1500da56265b8e2e5246d4f44120e555545f16b0d41abbfce64756e4016d953103134d1a334009d12b1b0f64a6bce89adf589e89b793b601551b74e5ba8566bb2e95b1551597577c20e9f1afef9021e6ea34ae56619dd185c83ec65669c29aab8564f00c85f51bf614079e72a8315ed6b9b7d8a910898c6e391886427e4984792ef0f0df2cea453cb90040dec020b44c97659cda5681f5092bcce5bbfdd0bb28484262a1d5d3f456259e0095c1c1e696280117b7f3558f8a98b93b32ea9748648922b40a3e2fea0a02c327e4ba49c477e8a1fd6b52a6f79464671d0465ab591bf995fa548222df60618ac30550cc59a382028530820281300e0603551d0f0101ff04040302020430260603551d25041f301d06082b0601050507030206082b0601050507030106022a030603810b01300f0603551d130101ff040530030101ff305f06082b0601050507010104533051302306082b060105050730018617687474703a2f2f6f6373702e6578616d706c652e636f6d302a06082b06010505073002861e687474703a2f2f6372742e6578616d706c652e636f6d2f6361312e63727430620603551d11045b30598210746573742e6578616d706c652e636f6d8111676f7068657240676f6c616e672e6f726787047f000001871020014860000020010000000000000068861a68747470733a2f2f666f6f2e636f6d2f776962626c6523666f6f300f0603551d2004083006300406022a033081df0603551d1e0481d73081d4a061300e820c2e6578616d706c652e636f6d300d820b6578616d706c652e636f6d300a8708c0a80000ffff0000300a870801000000ff0000003011810f666f6f406578616d706c652e636f6d300a86082e6261722e636f6d300986076261722e636f6da16f3011820f6261722e6578616d706c652e636f6d3022872020010db8000000000000000000000000ffffffffffff00000000000000000000300e810c2e6578616d706c652e636f6d300d810b6578616d706c652e636f6d300b86092e626172322e636f6d300a8608626172322e636f6d30570603551d1f0450304e3025a023a021861f687474703a2f2f63726c312e6578616d706c652e636f6d2f6361312e63726c3025a023a021861f687474703a2f2f63726c322e6578616d706c652e636f6d2f6361312e63726c301606032a0304040f657874726120657874656e73696f6e300d0603551d0e040604040403020130050603290000038202940039434807a0ef1e5749df19521788e2e2e38158b0c3459ff89f743c0e7241c196e8746ffa856096bf1c72ff93b4b71e9899d49ea53b6371092102ecca18f65d6b49a0831f908be9e86ce54155d47e323fedc45963ebf2a2840d59e7b1bbc1890f8655d88feab37198d3a094207f92d75e7bae3975d516bc4f480e839a97c11a048f0899e05f681619a44af2a9c7018a611023b143c7e951d4fe762b587edb5270585175b05c720ec7a2c127491f942dc3c2ac7e46f77f28d3210f7138969bd63df2e6fd362ed4f54e59bb761933c11ab5a3de0e193aa156520560d6543183586a59c471a6f5f229af840a7be7d23a1728239081c039586a6acca1f2bd15c4c209c5dd448d5c55ccc22234156afca3ee949b491f94f32affd4cf3afb641be65e57047324af173f769c7ee5020941c6b8b1afec2f20d769a65f2ce7d39e8440f99fe62caa6a63b0d3f065d756e0d3496e7ad2f87924a57d8c4ab2984931543a4ccf950920990197aae90d1d8e8087f51833e3dbf5d075b734451973f87ec92d051d6b42a28d57602c96850f4660a61987d9f89025234d5fcf06d7f3e21c88c159cb99f6c1205b98e6482076668893519215f195372c73107ad277634ccb2e755986f9bd3ace4591bf6f63afc590d7a764e98350bd1e1c8b009c95aaa426f6be4e790d8d34d74bd292a756fdeab0ac3eebd28e6e66cbd4a9365388d5c64eb667d39f69a492661ccc3105f4bdd51d5b4bfc8e9c5ed64d494b3a072628ca4514074914a7496b35780606e4b778a45066e18a4b09a11a996bbdba74c5c474b47b5f2e61853035820d4ab0e56edc52d749f2df94278d1c53d2066d125331c35a8b2a48d8cea8f10dab06fed22b8c4779a382109bb5da4fb496acf4becf48ec926c16d8d25498f38adfc7486b29ee7b0806ce6ab62a0b44
	//cert, err := x509.ParseCertificate(derBytes)

	genPem("CERTIFICATE", derBytes)
}

func parseCIDR(s string) *net.IPNet {
	_, net, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return net
}

func parseURI(s string) *url.URL {
	uri, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return uri
}
