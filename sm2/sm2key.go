package sm2

import (
	"math/big"
)

// PublicKey represents an ECDSA public key.
type PublicKey struct {
	param *SM2Param
	X, Y *big.Int
}

// PrivateKey represents a ECDSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

type sm2Signature struct {
	R, S *big.Int
}

