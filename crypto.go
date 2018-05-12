package main

import (
	"crypto/sha256"
	"errors"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
)

// Hash160 hash160
func Hash160(data []byte) []byte {
	return btcutil.Hash160(data)
}

// Hash256 hash256
func Hash256(data []byte) []byte {
	h0 := sha256.Sum256(data)
	h1 := sha256.Sum256(h0[:])
	return h1[:]
}

// CheckEncode base58 encode
func CheckEncode(data []byte, ver byte) string {
	return base58.CheckEncode(data, ver)
}

// CheckDecode base58 decode
func CheckDecode(data string) ([]byte, byte, error) {
	return base58.CheckDecode(data)
}

// Signer singer
type Signer interface {
	PrivateBytes() []byte
	PublicBytes() []byte
	Sign(data []byte) ([]byte, error)
	PublicBytesAlt() []byte
}

// NewKey generate key pair
func NewKey() (Signer, error) {
	key, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}
	return &signer256{key, key.PubKey(), true}, nil
}

// NewSigner new signer
func NewSigner(data []byte) (Signer, error) {
	cmp := false
	if len(data) == 33 {
		if data[32] == 0x01 {
			cmp = true
		} else {
			return nil, errors.New("malformed.key")
		}
	} else if len(data) != 32 {
		return nil, errors.New("malformed.key")
	}
	key, pub := btcec.PrivKeyFromBytes(btcec.S256(), data[:32])
	return &signer256{key, pub, cmp}, nil
}

type signer256 struct {
	key *btcec.PrivateKey
	pub *btcec.PublicKey
	cmp bool
}

func (t *signer256) PrivateBytes() []byte {
	if t.cmp {
		return append(t.key.Serialize(), 0x01)
	}
	return t.key.Serialize()
}

func (t *signer256) PublicBytes() []byte {
	if t.cmp {
		return t.pub.SerializeCompressed()
	}
	return t.pub.SerializeUncompressed()
}

func (t *signer256) PublicBytesAlt() []byte {
	if !t.cmp {
		return t.pub.SerializeCompressed()
	}
	return t.pub.SerializeUncompressed()
}

func (t *signer256) Sign(data []byte) ([]byte, error) {
	sig, err := t.key.Sign(data)
	if err != nil {
		return nil, err
	}
	return sig.Serialize(), nil
}
