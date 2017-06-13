package sm2

import (
	"testing"
	"crypto/rand"
	"math/big"
	"fmt"
	"encoding/asn1"
	"github.com/terasum/gm/sm2/sm2p256v1"
	"github.com/terasum/gm/common"
)

func TestGenerateKey(t *testing.T) {
	_, err := GenerateKey(sm2p256v1.SM2(),rand.Reader)
	if err != nil{
		t.Error("FAIL")
	}
}

func TestSign(t *testing.T) {
	priv := &PrivateKey{
		PublicKey: PublicKey{
			SM2Curve: sm2p256v1.SM2(),
		},
	}
//3045022100e5364aa91936b9691ce377bee718ebb8959697248d2b54ce967f0901acce0d9602207f7cf511473f3af975285b7ca23730678d005fb3e0c2fb72f9e065bb936f801f


	priv.D,_ = new(big.Int).SetString("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",16)
	priv.PublicKey.X,_ = new(big.Int).SetString("0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A",16)
	priv.PublicKey.Y,_ = new(big.Int).SetString("7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857",16)

	msg := "message digest"
	fmt.Println("msg: ", common.Bytes2Hex([]byte(msg)))

	r,s,err := Sign(rand.Reader,priv,[]byte(msg))
	if err != nil{
		t.Error("FAIL")
	}
	t.Log(common.Bytes2Hex(r.Bytes()))
	t.Log(common.Bytes2Hex(s.Bytes()))


	t.Log(Verify(&priv.PublicKey,[]byte(msg),r,s))
}

func TestVerify(t *testing.T) {
	pub := &PublicKey{
		SM2Curve: sm2p256v1.SM2(),
	}
	pub.X,_ = new(big.Int).SetString("7EA464762C333762D3BE8A04536B22955D97231062442F81A3CFF46CB009BBDB",16)
	pub.Y,_ = new(big.Int).SetString("B0F30E61ADE5705254D4E4E0C0745FB3BA69006D4B377F82ECEC05ED094DBE87",16)

	msg := "from=0x856e2b9a5fa82fd1b031d1ff6863864dbac7995d&to=0x794bf01ab3d37df2d1ea1aa4e6f4a0e988f4dea5&value=0x35&timestamp=0x14c3e11c1d4e427c&nonce=0x1d6522b27d9929"
	// signature der
	signder := "3045022100877b81a8024196dc4531558047546725aaff6138d2ab935fd7a34a31c9b11ecb0220476cfb9ad92ba9a9fbddbd9fd6595d46b7024d658806c3b2df911b5723987b29"
	sign := new(sm2Signature)
	asn1.Unmarshal(common.Hex2Bytes(signder),sign)

	f := Verify(pub,[]byte(msg),sign.R,sign.S)
	fmt.Println(f)
}


func BenchmarkVerify(b *testing.B) {
	pub := &PublicKey{
		SM2Curve: sm2p256v1.SM2(),
	}
	pub.X,_ = new(big.Int).SetString("7EA464762C333762D3BE8A04536B22955D97231062442F81A3CFF46CB009BBDB",16)
	pub.Y,_ = new(big.Int).SetString("B0F30E61ADE5705254D4E4E0C0745FB3BA69006D4B377F82ECEC05ED094DBE87",16)

	msg := "from=0x856e2b9a5fa82fd1b031d1ff6863864dbac7995d&to=0x794bf01ab3d37df2d1ea1aa4e6f4a0e988f4dea5&value=0x35&timestamp=0x14c3e11c1d4e427c&nonce=0x1d6522b27d9929"
	// signature der
	signder := "3045022100877b81a8024196dc4531558047546725aaff6138d2ab935fd7a34a31c9b11ecb0220476cfb9ad92ba9a9fbddbd9fd6595d46b7024d658806c3b2df911b5723987b29"
	sign := new(sm2Signature)
	asn1.Unmarshal(common.Hex2Bytes(signder),sign)

	for i:=0 ;i < b.N; i++{
		Verify(pub,[]byte(msg),sign.R,sign.S)
	}
}