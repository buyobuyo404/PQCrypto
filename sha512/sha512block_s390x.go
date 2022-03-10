// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha512

import (
	//"github.com/mercury/mercuryPQCrypto/internal/cpu"
	"github.com/mercury/mercuryPQCrypto/internal/cpu"
)

var useAsm = cpu.S390X.HasSHA512