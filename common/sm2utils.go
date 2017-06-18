package common

import (
	"encoding/hex"
	"math/big"
)

func Bytes2Hex(d []byte) string {
	return hex.EncodeToString(d)
}

func Hex2Bytes(str string) []byte {
	if len(str)>=2 && str[0:2] == "0x" {
		str = str[2:]
	}
	h, _ := hex.DecodeString(str)

	return h
}

func BytesToBig(data []byte) *big.Int {
	n := new(big.Int)
	n.SetBytes(data)

	return n
}

func BigToBytes(num *big.Int, base int) []byte {
	ret := make([]byte, base/8)

	if len(num.Bytes()) > base/8 {
		return num.Bytes()
	}

	return append(ret[:len(ret)-len(num.Bytes())], num.Bytes()...)
}