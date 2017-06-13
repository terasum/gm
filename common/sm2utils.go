package common
import "encoding/hex"

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
