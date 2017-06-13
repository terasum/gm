package sm2p256v1

import (
	"testing"

	"math/big"
	"fmt"
	"crypto/rand"
	"encoding/hex"
)

func TestOnCurve(t *testing.T) {
	sm2 := SM2()
	if !sm2.IsOnCurve(sm2.Params().Gx, sm2.Params().Gy) {
		t.Errorf("FAIL")
	}
}

func TestOffCurve(t *testing.T) {
	sm2 := SM2()
	x, y := new(big.Int).SetInt64(1), new(big.Int).SetInt64(1)
	if sm2.IsOnCurve(x, y) {
		t.Errorf("FAIL: point off curve is claimed to be on the curve")
	}
	b := Marshal(sm2, x, y)
	x1, y1 := Unmarshal(sm2, b)
	if x1 != nil || y1 != nil {
		t.Errorf("FAIL: unmarshaling a point not on the curve succeeded")
	}
}

type baseMultTest struct {
	k    string
	x, y string
}

var sm2BaseMultTests = []baseMultTest{
	{
		"63577cd6e65ee4ff4615a65bd97585421ebedc9bbe8d22fdb12819996e69779a",
		"2c2ac3db02f8dc337394dc6134c5de3f64a99c2ff1a2c2796cde7d845783530a",
		"1753c4822febc5b736dd3e1687856d3cdb40de1539799885f4287ab77aed0be9",
	},
	{
		"03d25be47393b68d9ac75488dc1509375507af8016073edc20a3a263fae18ecf",
		"fef4da60093617d046ca68a1c18f1b46f27c77af400763cc59a813d633fe59fc",
		"1338135020cb2cd7ec755db9a4eef290892d65e1d42f3f510a3e432c564da9e9",

	},
	{
		"71f6d7112fd24c46da24dfdcd317ab946bcf43f0cb26fecade3bd5e931929734",
		"d1a72c605dfa55ed4e9fc939b92779b634070023b1c28c0305722ed8e81fed4d",
		"53b110cec58a6e1cc0b24bce1ad15c280360a6ed995ec4c0b39463c176efa0fe",
	},
	{
		"c6c010d0a8c3d0593b6dadb33a7eb360752838134c8fe092fedc7503aa18e01e",
		"205fdb605069ff880c16197b8adaa7457ae59cee6a829ea6bf3a350adc319f6d",
		"f7631ee4c94f2a96c82a7fed0538fd102d36c33e5ccf710c11d4719329d689a2",
	},
	{
		"7ab9fd56c70acc1a083da1a3049c607df55f13a98e4abab565f24e943749c297",
		"bbecaa44759f1629dbdbf1a238ab89aaa5d7042e35a6e60c51ddf6b6d5c47dac",
		"67425b9496f96c7cc62e2a04b5594183085177bab3639ab649f7d5cd5bb6d556",
	},
	{
		"fd37d2dd198b6bcdd15086ba7880040e1cb558ea0fe6d1e6f6069a78293d18ce",
		"e290cbf7d2634d7b8e2d9296eab858eccc3ce2afb33508f1b754ea97e98991cf",
		"45d35ae41641739e585fa4f534ca56df0839bb52ba97ec610bcebb8e0967fc63",
	},
	{
		"4447e0b58efa083f62b0f3ae69b8611a998c508a738519648c7aa761858b7f4e",
		"7e8f40b4f9014b473e108fa51f06d6d76e6cd97ffc0b3ae38b5f825b4d1f787a",
		"dce1283c48b01dd2318272b7c222e85ef0f6231a2ed3d5c2c0e89b15db2eb8a2",
	},
	{
		"b3da2f77f6f518c8d1ce332fd3e9d98ea108b3e58835ae4294fc7f7ce4631f63",
		"f729775c31444b31514fee8c12f8c54455581f70de93823b2a6b234f0a2fe033" ,
		"f6101827d9ce79da11e055acb42ed69aa4e0a6a79560c6802e4dd85d4e65ae28",
	},
	{
		"b3da2f77f6f518c8d1ce332fd3e9d98ea108b3e58835ae4294fc7f7ce4631f63",
		"f729775c31444b31514fee8c12f8c54455581f70de93823b2a6b234f0a2fe033",
		"f6101827d9ce79da11e055acb42ed69aa4e0a6a79560c6802e4dd85d4e65ae28",
	},
	{
		"b3da2f77f6f518c8d1ce332fd3e9d98ea108b3e58835ae4294fc7f7ce4631f63",
		"f729775c31444b31514fee8c12f8c54455581f70de93823b2a6b234f0a2fe033",
		"f6101827d9ce79da11e055acb42ed69aa4e0a6a79560c6802e4dd85d4e65ae28",
	},
	{
		"39854BD0BDF491F1874ADB38AE8639ABB03245DEBB36773934959B93D0E825DA",
		"ff1d78ed5a7fdb906d522ff2173929faa457b28c309518ca9f4348968844b35f",
		"149484b01876329807b23eaa011964731686feefd8f1dc11e9ea79cb11cff548",
	},
}

func TestBaseMult(t *testing.T) {
	sm2 := SM2()
	for i, e := range sm2BaseMultTests {
		k, ok := new(big.Int).SetString(e.k, 16)
		if !ok {
			t.Errorf("%d: bad value for k: %s", i, e.k)
		}
		x, y := sm2.ScalarBaseMult(k.Bytes())
		if fmt.Sprintf("%x", x) != e.x || fmt.Sprintf("%x", y) != e.y {
			t.Errorf("%d: bad output for k=%s: got (%x, %x), want (%s, %s)", i, e.k, x, y, e.x, e.y)
		}
		if testing.Short() && i > 5 {
			break
		}
	}
}
//
func TestGenericBaseMult(t *testing.T) {
	// We use the SM2P256 CurveParams directly in order to test the generic implementation.
	sm2 := SM2()
	for i, e := range sm2BaseMultTests {
		k, ok := new(big.Int).SetString(e.k, 16)
		if !ok {
			t.Errorf("%d: bad value for k: %s", i, e.k)
		}
		x, y := sm2.ScalarBaseMult(k.Bytes())
		if fmt.Sprintf("%x", x) != e.x || fmt.Sprintf("%x", y) != e.y {
			t.Errorf("%d: bad output for k=%s: got (%x, %x), want (%s, %s)", i, e.k, x, y, e.x, e.y)
		}
		if testing.Short() && i > 5 {
			break
		}
	}
}


func TestInfinity(t *testing.T) {
	tests := []struct {
		name  string
		curve SM2Curve
	}{
		{"sm2p256", SM2()},
	}

	for _, test := range tests {
		curve := test.curve
		x, y := curve.ScalarBaseMult(nil)
		if x.Sign() != 0 || y.Sign() != 0 {
			t.Errorf("%s: x^0 != ∞", test.name)
		}
		x.SetInt64(0)
		y.SetInt64(0)

		x2, y2 := curve.Double(x, y)
		if x2.Sign() != 0 || y2.Sign() != 0 {
			t.Errorf("%s: 2∞ != ∞", test.name)
		}

		baseX := curve.Params().Gx
		baseY := curve.Params().Gy

		x3, y3 := curve.Add(baseX, baseY, x, y)
		if x3.Cmp(baseX) != 0 || y3.Cmp(baseY) != 0 {
			t.Errorf("%s: x+∞ != x", test.name)
		}

		x4, y4 := curve.Add(x, y, baseX, baseY)
		if x4.Cmp(baseX) != 0 || y4.Cmp(baseY) != 0 {
			t.Errorf("%s: ∞+x != x", test.name)
		}
	}
}

func BenchmarkBaseMult(b *testing.B) {
	b.ResetTimer()
	sm2 := SM2()
	e := sm2BaseMultTests[8]
	k, _ := new(big.Int).SetString(e.k, 16)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		sm2.ScalarBaseMult(k.Bytes())
	}
}


func BenchmarkScalarMultP256(b *testing.B) {
	b.ResetTimer()
	sm2 := SM2()
	_, x, y, _ := GenerateKey(sm2, rand.Reader)
	priv, _, _, _ := GenerateKey(sm2, rand.Reader)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		sm2.ScalarMult(x, y, priv)
	}
}

func TestMarshal(t *testing.T) {
	sm2 := SM2()
	_, x, y, err := GenerateKey(sm2, rand.Reader)
	if err != nil {
		t.Error(err)
		return
	}
	serialized := Marshal(sm2, x, y)
	xx, yy := Unmarshal(sm2, serialized)
	if xx == nil {
		t.Error("failed to unmarshal")
		return
	}
	if xx.Cmp(x) != 0 || yy.Cmp(y) != 0 {
		t.Error("unmarshal returned different values")
		return
	}
}

func TestSM2P256Overflow(t *testing.T) {
	// This tests for a specific bug in the P224 implementation.
	sm2 := SM2()
	pointData, _ := hex.DecodeString("04f729775c31444b31514fee8c12f8c54455581f70de93823b2a6b234f0a2fe033f6101827d9ce79da11e055acb42ed69aa4e0a6a79560c6802e4dd85d4e65ae28")
	x, y := Unmarshal(sm2, pointData)
	if !sm2.IsOnCurve(x, y) {
		t.Error("SM2 failed to validate a correct point")
	}
}

