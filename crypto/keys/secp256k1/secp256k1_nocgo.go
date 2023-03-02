//go:build !libsecp256k1_sdk
// +build !libsecp256k1_sdk

package secp256k1

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	secp256k1 "github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	secp_ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/tendermint/tendermint/crypto"
)

// used to reject malleable signatures
// see:
//   - https://github.com/ethereum/go-ethereum/blob/f9401ae011ddf7f8d2d95020b7446c17f8d98dc1/crypto/signature_nocgo.go#L90-L93
//   - https://github.com/ethereum/go-ethereum/blob/f9401ae011ddf7f8d2d95020b7446c17f8d98dc1/crypto/crypto.go#L39
var secp256k1halfN = new(big.Int).Rsh(secp256k1.S256().N, 1)

// Sign creates an ECDSA signature on curve Secp256k1, using SHA256 on the msg.
// The returned signature will be of the form R || S (in lower-S form).
func (privKey *PrivKey) Sign(msg []byte) ([]byte, error) {
	sig, err := privKey.Sign(crypto.Sha256(msg))
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// VerifySignature verifies a signature of the form R || S.
// It rejects signatures which are not in lower-S form.
func (pubKey PubKey) VerifySignature(msg []byte, sigStr []byte) bool {
	if len(sigStr) != 64 {
		return false
	}
	var r, s btcec.ModNScalar
	if r.SetByteSlice(sigStr[:32]) {
		return false // overflow
	}
	if s.SetByteSlice(sigStr[32:]) {
		return false
	}
	// parse the signature:
	signature := signatureFromBytes(sigStr)
	pub, err := secp256k1.ParsePubKey(pubKey.Key)
	if err != nil {
		return false
	}
	// Reject malleable signatures. libsecp256k1 does this check but btcec doesn't.
	// see: https://github.com/ethereum/go-ethereum/blob/f9401ae011ddf7f8d2d95020b7446c17f8d98dc1/crypto/signature_nocgo.go#L90-L93
	//secp256k1halfN
	if s.IsOverHalfOrder() {
		return false
	}

	return signature.Verify(crypto.Sha256(msg), pub)
}

// Read Signature struct from R || S. Caller needs to ensure
// that len(sigStr) == 64.
func signatureFromBytes(sigStr []byte) *secp_ecdsa.Signature {
	sig, err := ecdsa.ParseSignature(sigStr)

	if err != nil {
		panic("error parsing signature")
	}

	return sig
}
