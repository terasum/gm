package sm2

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"github.com/terasum/gm/common"
	"github.com/terasum/gm/sm2/sm2p256v1"
	"github.com/terasum/gm/sm3"
)

// PublicKey represents an ECDSA public key.
type PublicKey struct {
	sm2p256v1.SM2Curve
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

// A invertible implements fast inverse mod Curve.Params().N
type invertible interface {
	// Inverse returns the inverse of k in GF(P)
	Inverse(k *big.Int) *big.Int
}

// combinedMult implements fast multiplication S1*g + S2*p (g - generator, p - arbitrary point)
type combinedMult interface {
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

const (
	aesIV = "IV for ECDSA CTR"
)

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() *PublicKey {
	return &priv.PublicKey
}

// Sign signs msg with priv, reading randomness from rand. This method is
// intended to support keys where the private part is kept in, for example, a
// hardware module. Common uses should use the Sign function in this package
// directly.
func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := Sign(rand, priv, msg)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(sm2Signature{r, s})
}

var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(c sm2p256v1.SM2Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// GenerateKey generates a public and private key pair.
func GenerateKey(c sm2p256v1.SM2Curve, rand io.Reader) (*PrivateKey, error) {
	k, err := randFieldElement(c, rand)
	if err != nil {
		return nil, err
	}

	priv := new(PrivateKey)
	priv.PublicKey.SM2Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
func hashToInt(hash []byte, c sm2p256v1.SM2Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method.
// This has better constant-time properties than Euclid's method (implemented
// in math/big.Int.ModInverse) although math/big itself isn't strictly
// constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

var errZeroParam = errors.New("zero parameter")

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length.  It
// returns the signature as a pair of integers. The security of the private key
// depends on the entropy of rand.

// sm2 sign step:
// 1. get private key dA
// 2. calc the public key pA = da * G
// 3. get Za = SM3(ENLa || ID || a || b || G || pA)
// 4. get e = SM3(Za || M)
// 5. get random k
// 6. get point (x1,y1) = k * G
// 7. get r = (e + x1) mod n
// 8. get s = ((k - r * dA)/(1+dA)) mod n

func Sign(rand io.Reader, priv *PrivateKey, msg []byte) (r, s *big.Int, err error) {
	// step 1. get private key da
	// step 2. get public key pA da * G
	// step 3. get Za
	h := sm3.SM3New()
	ENTL1 := "00"
	h.Write(common.Hex2Bytes(ENTL1))
	ENTL2 := "80"
	h.Write(common.Hex2Bytes(ENTL2))
	userId := "31323334353637383132333435363738"
	//userId := "414C494345313233405941484F4F2E434F4D"

	h.Write(common.Hex2Bytes(userId))
	a := "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
	//a:= "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
	h.Write(common.Hex2Bytes(a))
	b := "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
	//b:= "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
	h.Write(common.Hex2Bytes(b))
	xG := "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
	//xG := "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
	h.Write(common.Hex2Bytes(xG))
	yG := "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
	//yG := "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
	h.Write(common.Hex2Bytes(yG))
	h.Write(priv.PublicKey.X.Bytes())
	//h.Write(sm2utils.Hex2Bytes("0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A"))

	h.Write(priv.PublicKey.Y.Bytes())
	//h.Write(sm2utils.Hex2Bytes("7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857"))

	Za := h.Sum(nil)
	fmt.Println("Za ", common.Bytes2Hex(Za))
	// step get e
	h2 := sm3.SM3New()
	h2.Write(Za)
	h2.Write(msg)
	eb := h2.Sum(nil)[:32]
	fmt.Println("e ", common.Bytes2Hex(eb))

	//get random k
	// Get min(log2(q) / 2, 256) bits of entropy from rand.
	entropylen := (priv.SM2Curve.Params().BitSize + 7) / 16
	if entropylen > 32 {
		entropylen = 32
	}
	entropy := make([]byte, entropylen)
	_, err = io.ReadFull(rand, entropy)
	if err != nil {
		return
	}

	// Initialize an SHA-512 hash context; digest ...

	//md := sha512.New()
	//md.Write(priv.D.Bytes()) // the private key,
	//md.Write(entropy)        // the entropy,
	//md.Write(hash)           // and the input hash;
	//key := md.Sum(nil)[:32]  // and compute ChopMD-256(SHA-512),
	// which is an indifferentiable MAC.

	// step 5. get ramdom k
	// Create an AES-CTR instance to use as a CSPRNG.
	block, err := aes.NewCipher(eb)
	if err != nil {
		return nil, nil, err
	}

	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	// See [NSA] 3.4.1
	c := priv.PublicKey.SM2Curve
	N := c.Params().N
	// get e
	e := hashToInt(eb, c)

	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	var k *big.Int
	for {
		// step 7 get r
		for {
			k, err = randFieldElement(c, csprng)
			if err != nil {
				r = nil
				return
			}
			// for debug
			//k,_ = k.SetString("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F",16)
			fmt.Println("k: ", common.Bytes2Hex(k.Bytes()))
			x1, y1 := priv.SM2Curve.ScalarBaseMult(k.Bytes())
			fmt.Println("x1: ", common.Bytes2Hex(x1.Bytes()))
			fmt.Println("y1: ", common.Bytes2Hex(y1.Bytes()))

			// r = e + x1 (mod n)
			r = new(big.Int).Add(x1, e)
			r.Mod(r, N)
			//until the sign not equal 0
			/* check r != 0 && r + k != n */
			if r.Sign() != 0 && r.Add(r, k).Sub(r, N).Int64() != 0 {
				break
			}
		}

		//step 8. get s = ((k - r * dA)/(1+dA)) mod n
		/* s = ((1 + dA)^-1 * (k - r * dA)) mod n */
		//r * dA
		tmp1 := new(big.Int).Mul(priv.D, r)
		// k - r * dA
		tmp2 := k.Sub(k, tmp1)
		// 1 + dA
		tmp3 := new(big.Int).Add(new(big.Int).SetInt64(1), priv.D)
		// (1 + dA)^-1
		//s := tmp3.Exp(tmp3,new(big.Int).SetInt64(-1),new(big.Int).SetInt64(0))
		s = tmp3.ModInverse(tmp3, N)
		s.Mul(s, tmp2)
		s.Mod(s, N) // N != 0
		if s.Sign() != 0 {
			break
		}
	}

	return
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
// sm2 verify step
// 1. get public key pA
// 2. get Za = SM3(ENTLa || ID || a || b || G || pA)
// 3. e = SM3(Za || M)
// 4. t = (r+s) mod n
// 5. get point (x1',y1') = s * G + t * pA
// 6. R = (e + x1') mod n
// 7 check R == r ?

func Verify(pub *PublicKey, msg []byte, r, s *big.Int) bool {
	// get eb
	eb := preHandle(pub, msg)
	//fmt.Println("e ", sm2utils.Bytes2Hex(eb))

	c := pub.SM2Curve
	N := c.Params().N
	// get e
	e := hashToInt(eb, c)

	// setp 3. get t  = r + s mod n
	t := s.Mul(s, r)
	t.Mod(t, N)

	//(x1',y1') = s * G + t * pA
	tmpx1, tmpy1 := pub.SM2Curve.ScalarBaseMult(s.Bytes())
	tmpx2, tmpy2 := pub.SM2Curve.ScalarMult(pub.X, pub.Y, t.Bytes())
	x1_, y1_ := pub.SM2Curve.Add(tmpx1, tmpy1, tmpx2, tmpy2)
	if x1_.Sign() == 0 && y1_.Sign() == 0 {
		return false
	}

	//R = (e + x1') mod n
	R := e.Add(e, x1_)
	R.Mod(r, N)

	//check R == r ?
	return R.Cmp(r) == 0
}

type zr struct {
	io.Reader
}

// Read replaces the contents of dst with zeros.
func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}
//prehandle get the e for sign
func preHandle(pub *PublicKey, msg []byte) []byte {
	h := sm3.SM3New()
	ENTL1 := "00"
	h.Write(common.Hex2Bytes(ENTL1))
	ENTL2 := "80"
	h.Write(common.Hex2Bytes(ENTL2))
	userId := "31323334353637383132333435363738"

	h.Write(common.Hex2Bytes(userId))
	a := "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
	h.Write(common.Hex2Bytes(a))
	b := "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
	h.Write(common.Hex2Bytes(b))
	xG := "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
	h.Write(common.Hex2Bytes(xG))
	yG := "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
	h.Write(common.Hex2Bytes(yG))
	h.Write(pub.X.Bytes())
	h.Write(pub.Y.Bytes())

	Za := h.Sum(nil)
	// step get e
	h2 := sm3.SM3New()
	h2.Write(Za)
	h2.Write(msg)
	eb := h2.Sum(nil)[:32]
	return eb
}
