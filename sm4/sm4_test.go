package SM4

import (
	"testing"
)

func TestSHL(t *testing.T) {
	data := [4]byte{0x00,0x00,0x00,0x01}
	t.Log(data)
	t.Log(SHL(data,1))
}

func TestROTL(t *testing.T) {
	data := [4]uint8{0x80,0x00,0x00,0x00}
	t.Log(data)
	t.Log(ROTL(data,1))
}

func TestXOR(t *testing.T) {
	data1 := [4]byte{0x00,0x00,0x00,0x02}
	data2 := [4]byte{0x00,0x00,0x00,0x01}
	t.Log(XOR(data1,data2))
}

func TestSUB(t *testing.T) {
	t.Log(SUB(byte(0x03),byte(0x01)))
}
