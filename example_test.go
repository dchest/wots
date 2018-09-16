// Copyright 2012 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wots_test

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/dchest/wots"
)

func Example() {
	// Define scheme using SHA-256. There's no need to always
	// create this scheme, it can be a global variable.
	var wotssha256 = wots.NewScheme(sha256.New, rand.Reader)

	// Generating key pair.
	privateKey, publicKey, err := wotssha256.GenerateKeyPair()
	if err != nil {
		panic("key generation failed")
	}

	// Signing.
	message := []byte("Hello world!")
	signature, err := wotssha256.Sign(privateKey, message) // => 1120-byte signature
	if err != nil {
		panic("signature calculation failed")
	}

	// After signing once, private key must not be used to sign more messages!
	// This is a one-time signature scheme.

	// Verifying.
	if wotssha256.Verify(publicKey, message, signature) {
		fmt.Println("verification succeeded")
	} else {
		fmt.Println("verification failed")
	}
}
