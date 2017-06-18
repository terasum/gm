package sm2

import (
	"sync"
	"hyperchain/common"
	"github.com/terasum/gm/sm3"
)

type SM2Param struct {
	A []byte
	B []byte
	Entl1 []byte
	Entl2 []byte
	Userid []byte
	P []byte
	N []byte
	XG []byte
	YG []byte
	CurveType int `json:"sm2_curve_type"`
}
//测试系统参数
var sm2Test *SM2Param
//推荐系统参数
var sm2Recom *SM2Param

var once1 sync.Once
var once2 sync.Once
func init(){
	once1.Do(initSM2Test)
	once2.Do(initSM2Recom)
}

func initSM2Test(){
	sm2Test	= &SM2Param{
		A:common.Hex2Bytes("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"),
		B:common.Hex2Bytes("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"),
		Entl1:common.Hex2Bytes("00"),
		Entl2:common.Hex2Bytes("90"),
		Userid:common.Hex2Bytes("414C494345313233405941484F4F2E434F4D"),
		P:common.Hex2Bytes("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"),
		N:common.Hex2Bytes("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"),
		XG:common.Hex2Bytes("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"),
		YG:common.Hex2Bytes("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"),
		CurveType:0,
	}
}
func initSM2Recom(){
	sm2Recom = &SM2Param{
		A:common.Hex2Bytes("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"),
		B:common.Hex2Bytes("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
		Entl1:common.Hex2Bytes("00"),
		Entl2:common.Hex2Bytes("80"),
		Userid:common.Hex2Bytes("31323334353637383132333435363738"),
		P:common.Hex2Bytes("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
		N:common.Hex2Bytes("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
		XG:common.Hex2Bytes("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
		YG:common.Hex2Bytes("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
		CurveType:1,
	}
}

func GetSM2Test() *SM2Param{
	return sm2Test
}
func GetSM2Recom() *SM2Param{
	return sm2Recom
}
var a = 0;
func(p *SM2Param)preHandle(data []byte, pub *PublicKey)[]byte{
	h := sm3.SM3New()
	h.Write(p.Entl1)
	//fmt.Println("> Ent1",common.Bytes2Hex(p.Entl1))
	h.Write(p.Entl2)
	//fmt.Println("> Ent2",common.Bytes2Hex(p.Entl2))
	h.Write(p.Userid)
	//fmt.Println("> userid",common.Bytes2Hex(p.Userid))
	h.Write(p.A)
	//fmt.Println("> a",common.Bytes2Hex(p.A))
	h.Write(p.B)
	//fmt.Println("> b",common.Bytes2Hex(p.B))
	h.Write(p.XG)
	//fmt.Println("> xG",common.Bytes2Hex(p.XG))
	h.Write(p.YG)
	//fmt.Println("> yG",common.Bytes2Hex(p.YG))

	h.Write(pub.X.Bytes())
	//fmt.Println("> pubx: ",common.Bytes2Hex(pub.X.Bytes()))
	h.Write(pub.Y.Bytes())
	//fmt.Println("> puby: ",common.Bytes2Hex(pub.Y.Bytes()))
	Za := h.Sum(nil)
	//fmt.Println("> Za: ",common.Bytes2Hex(Za))

	//修改为sm3hash方法
	M_ := append(Za,data...)

	h2 := sm3.SM3New()
	h2.Write(M_)
	hash := h2.Sum(nil)
	//fmt.Println("> hash: ",common.Bytes2Hex(hash))
	return hash
}
