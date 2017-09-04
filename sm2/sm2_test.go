package sm2

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"github.com/terasum/gm/common"
)

func TestGetPrivateKey(t *testing.T) {
	key,err := GeneratePrivByC(1);
	if err != nil{
		t.Fatal(err)
	}
	assert.NotNil(t,key)
}
func TestGenerateP(t *testing.T) {
	key,err := GeneratePrivByC(1);
	if err != nil{
		t.Fatal(err)
	}
	assert.NotNil(t,key)
}
func TestPrivateKey_Sign(t *testing.T) {
	key,err := GeneratePrivByC(0);
	if err != nil{
		t.Fatal(err)
	}
	assert.NotNil(t,key)
	sign,err := key.Sign([]byte("msg"))
	if err != nil{
		t.Fatal(err)
	}
	assert.NotNil(t,sign)
}
func TestPublicKey_Verify(t *testing.T) {
	key,err := GeneratePrivByC(0);
	if err != nil{
		t.Fatal(err)
	}
	assert.NotNil(t,key)
	sign,err := key.Sign([]byte("msg"))
	if err != nil{
		t.Fatal(err)
	}
	assert.NotNil(t,sign)

	bool,err := key.PublicKey.Verify(sign,[]byte("msg"))
	if err != nil{
		t.Fatal(err)
	}
	assert.True(t,bool)
}

func BenchmarkPublicKey_Verify(b *testing.B) {
	key,err := GeneratePrivByC(0);
	if err != nil{
		b.Fatal(err)
	}
	sign,err := key.Sign([]byte("msg"))
		if err != nil{
			b.Fatal(err)
		}
	for i:=0;i<b.N;i++{
		_,err := key.PublicKey.Verify(sign,[]byte("msg"))
		if err != nil{
			b.Fatal(err)
		}
	}
}

func TestGeneratePrivateKey(t *testing.T) {
	privD :="1c488635a6e071cff1251de3d89014cfab366687876436e896330ef4a0337925";
	//pubX :="0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A";
	//pubY :="7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857";
	t.Log(len(common.Hex2Bytes(privD)))
 	priv,err := GetPrivateKey(common.Hex2Bytes(privD),1);
	if err != nil{
		t.Fatal(err)
	}
	t.Log(priv.D.String())
	t.Log(common.Bytes2Hex(priv.X.Bytes()))
	t.Log(priv.Y)

	//t.Log(len(common.Hex2Bytes(pubX)))
	//t.Log(len(common.Hex2Bytes(pubY)))
	//t.Log([]byte("msg"))
	//t.Log(len([]byte("msg")))
}

func TestPrivateKey_Sign2(t *testing.T) {
	key,err := GeneratePrivByC(0);
	if err != nil{
		t.Fatal(err)
	}
	t.Log("PriD",common.Bytes2Hex(key.D.Bytes()))
	t.Log("PubX",common.Bytes2Hex(key.X.Bytes()))
	t.Log("pubY",common.Bytes2Hex(key.Y.Bytes()))

	assert.NotNil(t,key)
	sign,err := key.Sign([]byte("message digest"))
	if err != nil{
		t.Fatal(err)
	}
	assert.NotNil(t,sign)
}

func TestPublicKey_Verify2(t *testing.T) {
	pubx := common.Hex2Bytes("09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020")
	puby := common.Hex2Bytes("ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13")
	 pub,err := GeneratePublicKey(pubx,puby,1)
	if err != nil{
		t.Fatal(err)
	}
	//t.Log(common.Bytes2Hex(pub.X.Bytes()))
	//t.Log(common.Bytes2Hex(pub.Y.Bytes()))
	msg := []byte("message digest");
	sign := common.Hex2Bytes("xx3046022100AD20BE832596D355FD6E952210A833D59C68E1B54000756F48816E3A5A049C8B022100C2C988DF85B03B446D21CAD9C11445D11F67748F002CF6ACD0AEC55BBD8D1290")
	bol,err := pub.Verify(sign,msg)
	assert.False(t,bol)
	assert.NotNil(t,err)
}
