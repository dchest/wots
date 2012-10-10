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
	var wotssha256 = wots.NewScheme(sha256.New)

	// Generating key pair.
	key, err := wotssha256.GenerateKey(rand.Reader)
	if err != nil {
		panic("key generation failed")
	}

	// Messages will be verified against this public key.
	publicKey := key.PublicKey // => 32-byte public key

	// Signing.
	message := []byte("Hello world!")
	signature := wotssha256.Sign(key, message) // => 1120-byte signature

	// After signing once, key can't be used to sign more messages.
	// For safety, private key bytes are destroyed, only key.PublicKey left.

	// Verifying.
	if wotssha256.Verify(publicKey, message, signature) {
		fmt.Println("verification successed")
	} else {
		fmt.Println("verification failed")
	}
}
