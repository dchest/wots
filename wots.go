// Copyright 2012, 2017 Dmitry Chestnykh. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package wots implements Winternitz-Lamport-Diffie one-time signature scheme.
//
// If the hash function is one-way and of sufficient length, the private key is
// random, not known to the attacker, and used to sign only one message, and
// there are no bugs in this implementation, it is infeasible to forge
// signatures (even on quantum computer, provided that it can't break the
// underlying hash function).
//
// Implementation details
//
// Cost/size trade-off parameter w=8 bits, which means that public key
// generation takes (n+2)*256+1 hash function evaluations, where n is hash
// output size in bytes. Similarly, on average, signing or verifying a single
// message take 1+((n+2)*255)/2 evaluations.
//
// Message hash is calculated with randomization as specified in NIST
// SP-800-106 "Randomized Hashing for Digital Signatures", with length
// of randomization string equal to the length of hash function output.
// The randomization string is prepended to the signature.
package wots

import (
	"bytes"
	"errors"
	"hash"
	"io"
)

// Scheme represents one-time signature signing/verification configuration.
type Scheme struct {
	digestSize int
	blockSize  int
	pubkeySize int
	chainFunc  func() hash.Hash
	hashFunc   func() hash.Hash
	rand       io.Reader
}

// NewScheme returns a new signing/verification scheme from the given function
// returning hash.Hash type and a random byte reader (must be cryptographically
// secure, such as crypto/rand.Reader).
//
// The hash function output size must have minimum 16 and maximum 128 bytes,
// otherwise GenerateKeyPair method will always return error.
//
// This variant of the function supports separate hash functions: (1) for
// chaining and (2) for message hashing and final hashing into public key.
func NewScheme2(h, chainFunc func() hash.Hash, rand io.Reader) *Scheme {
	return &Scheme{
		digestSize: h().Size(),
		blockSize:  chainFunc().Size(),
		pubkeySize: h().Size(),
		chainFunc:  chainFunc,
		hashFunc:   h,
		rand:       rand,
	}
}

// NewScheme returns a new signing/verification scheme from the given function
// returning hash.Hash type and a random byte reader (must be cryptographically
// secure, such as crypto/rand.Reader).
//
// The hash function output size must have minimum 16 and maximum 128 bytes,
// otherwise GenerateKeyPair method will always return error.
func NewScheme(h func() hash.Hash, rand io.Reader) *Scheme {
	return NewScheme2(h, h, rand)
}

// PrivateKeySize returns private key size in bytes.
func (s *Scheme) PrivateKeySize() int { return (s.digestSize + 2) * s.blockSize }

// PublicKeySize returns public key size in bytes.
func (s *Scheme) PublicKeySize() int { return s.pubkeySize }

// SignatureSize returns signature size in bytes.
func (s *Scheme) SignatureSize() int { return (s.digestSize+2)*s.blockSize + s.digestSize }

// PublicKey represents a public key.
type PublicKey []byte

// PrivateKey represents a private key.
type PrivateKey []byte

// hashBlock returns in hashed the given number of times: H(...H(in)).
// If times is 0, returns a copy of input without hashing it.
func hashBlock(h hash.Hash, in []byte, times int) (out []byte) {
	out = append(out, in...)
	for i := 0; i < times; i++ {
		h.Reset()
		h.Write(out)
		out = h.Sum(out[:0])
	}
	return
}

// GenerateKeyPair generates a new private and public key pair.
func (s *Scheme) GenerateKeyPair() (PrivateKey, PublicKey, error) {
	if s.digestSize < 16 || s.digestSize > 128 {
		return nil, nil, errors.New("wots: wrong hash output size")
	}
	// Generate random private key.
	privateKey := make([]byte, s.PrivateKeySize())
	if _, err := io.ReadFull(s.rand, privateKey); err != nil {
		return nil, nil, err
	}
	publicKey, err := s.PublicKeyFromPrivate(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

// PublicKeyFromPrivate returns a public key corresponding to the given private key.
func (s *Scheme) PublicKeyFromPrivate(privateKey PrivateKey) (PublicKey, error) {
	if len(privateKey) != s.PrivateKeySize() {
		return nil, errors.New("wots: private key size doesn't match the scheme")
	}

	// Create public key from private key.
	keyHash := s.hashFunc()
	blockHash := s.chainFunc()
	for i := 0; i < len(privateKey); i += s.blockSize {
		keyHash.Write(hashBlock(blockHash, privateKey[i:i+s.blockSize], 256))
	}
	return keyHash.Sum(nil), nil
}

// messageDigest returns a randomized digest of message with 2-byte checksum.
func messageDigest(h hash.Hash, r []byte, msg []byte) []byte {
	// Randomized hashing (NIST SP-800-106).
	//
	//  Padding: m = msg ‖ 0x80 [0x00...]
	//  Hashing: H(r ‖ m1 ⊕ r, ..., mL ⊕ r ‖ rv_length_indicator)
	//    where m1..mL are blocks of size len(r) of padded msg,
	//    and rv_length_indicator is 16-byte big endian len(r).
	//
	h.Write(r)
	rlen := len(r)
	tmp := make([]byte, rlen)
	for len(msg) >= rlen {
		for i, m := range msg[:rlen] {
			tmp[i] = m ^ r[i]
		}
		h.Write(tmp)
		msg = msg[rlen:]
	}
	for i := range tmp {
		tmp[i] = 0
	}
	copy(tmp, msg)
	tmp[len(msg)] = 0x80
	for i := range tmp {
		tmp[i] ^= r[i]
	}
	h.Write(tmp)
	tmp[0] = uint8(rlen >> 8)
	tmp[1] = uint8(rlen)
	h.Write(tmp[:2])
	d := h.Sum(nil)

	// Append checksum of digest bits.
	var sum uint16
	for _, v := range d {
		sum += 256 - uint16(v)
	}
	return append(d, uint8(sum>>8), uint8(sum))
}

// Sign signs an arbitrary length message using the given private key and
// returns signature.
//
// IMPORTANT: Do not use the same private key to sign more than one message!
// It's a one-time signature.
func (s *Scheme) Sign(privateKey PrivateKey, message []byte) (sig []byte, err error) {
	if len(privateKey) != s.PrivateKeySize() {
		return nil, errors.New("wots: private key size doesn't match the scheme")
	}

	blockHash := s.chainFunc()

	// Generate message randomization parameter.
	r := make([]byte, s.digestSize)
	if _, err := io.ReadFull(s.rand, r); err != nil {
		return nil, err
	}

	// Prepend randomization parameter to signature.
	sig = append(sig, r...)

	for _, v := range messageDigest(s.hashFunc(), r, message) {
		sig = append(sig, hashBlock(blockHash, privateKey[:s.blockSize], int(v))...)
		privateKey = privateKey[s.blockSize:]
	}
	return
}

// Verify verifies the signature of message using the public key,
// and returns true iff the signature is valid.
//
// Note: verification time depends on message and signature.
func (s *Scheme) Verify(publicKey PublicKey, message []byte, sig []byte) bool {
	if len(publicKey) != s.PublicKeySize() || len(sig) != s.SignatureSize() {
		return false
	}
	d := messageDigest(s.hashFunc(), sig[:s.digestSize], message)
	sig = sig[s.digestSize:]
	keyHash := s.hashFunc()
	blockHash := s.chainFunc()
	for _, v := range d {
		keyHash.Write(hashBlock(blockHash, sig[:s.blockSize], 256-int(v)))
		sig = sig[s.blockSize:]
	}
	return bytes.Equal(keyHash.Sum(nil), publicKey)
}
