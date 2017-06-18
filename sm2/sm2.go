package sm2
/*
#cgo CFLAGS : -I/usr/local/include -I/lib/local/ssl/include -I/usr/local/opt/openssl/include
#cgo LDFLAGS: -lssl -lcrypto -ldl

#include <openssl/opensslconf.h>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "./libsm2/include/ossl_typ.h"
#include "./libsm2/include/ecdsa.h"
#include "./libsm2/include/ecdh.h"
#include "./libsm2/obj_mac.h"
#include "./libsm2/sm2.h"
#include "./libsm2/include/sm3.h"
#include "./libsm2/sm2.c"

*/
import "C"

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"unsafe"
	"io"
	"math/big"
	"crypto/rand"
	"fmt"
	"runtime"
)


func GeneratePrivByC(curveType int)(*PrivateKey,error){
	privkey := new(PrivateKey)
	ec_key := C.EC_KEY_new();
	var ec_group *C.EC_GROUP
	if curveType == 0{
		privkey.param = GetSM2Test()
		ec_group = C.sm2_ec_group();
	}else if curveType ==1{
		privkey.param = GetSM2Recom()
		ec_group = C.sm2_ec_group2();
	}

	if ec_group == nil{
		return nil,errors.New(" EC_get_group failed!");
	}

	if C.EC_KEY_set_group(ec_key,ec_group) != C.int(1) {
		return nil,errors.New("Error in initializeCrypto, EC_KEY_set_group failed!");
	}
	defer C.EC_GROUP_free(ec_group);
	// Segfault at this position
	if(C.EC_KEY_generate_key(ec_key) != C.int(1)){
		return nil,errors.New("Error in generateKeys, EC_KEY_generate_key failed!");
	}
	//取得公钥的x 和 y
	pub_key_x := C.BN_new()
	if pub_key_x == nil{
		return nil,errors.New("malloc pub_key_x failed")
	}
	defer C.BN_free(pub_key_x)

	pub_key_y := C.BN_new()
	if pub_key_y == nil{
		return nil,errors.New("malloc pub_key_y failed")
	}
	defer C.BN_free(pub_key_y)

	//BIGNUM
	priv_key := C.EC_KEY_get0_private_key(ec_key);
	if priv_key == nil{

		return nil,errors.New("get priv_key failed")
	}
	pub_key :=C.EC_KEY_get0_public_key(ec_key);
        if pub_key == nil{
		return nil,errors.New("get pub_key failed")
	}
	//然后将计算出来的各个值取得，并放入到前面new的ECKey中
	// get X and Y coords from pub_key
	if C.EC_POINT_get_affine_coordinates_GFp(ec_group, pub_key, pub_key_x, pub_key_y,
		nil) != C.int(1) {
		return nil, errors.New("EC_POINT_get_affine_coordinates_GFp failed")
	}
	privkey.D = new(big.Int)
	privkey.PublicKey.X = new(big.Int)
	privkey.PublicKey.Y  = new(big.Int)

	privkey_D := make([]byte, C.BN_num_bytes_not_a_macro(priv_key))
	privkey_PublicKey_X := make([]byte, C.BN_num_bytes_not_a_macro(pub_key_x))
	privkey_PublicKey_Y := make([]byte, C.BN_num_bytes_not_a_macro(pub_key_y))
	C.BN_bn2bin(priv_key, (*C.uchar)(unsafe.Pointer(&privkey_D[0])))
	C.BN_bn2bin(pub_key_x, (*C.uchar)(unsafe.Pointer(&privkey_PublicKey_X[0])))
	C.BN_bn2bin(pub_key_y, (*C.uchar)(unsafe.Pointer(&privkey_PublicKey_Y[0])))
	privkey.D.SetBytes(privkey_D)
	privkey.PublicKey.X.SetBytes(privkey_PublicKey_X)
	privkey.PublicKey.Y.SetBytes(privkey_PublicKey_Y)
	return privkey, nil
}

func GetPrivateKey(rnd []byte,curveType int)(*PrivateKey,error){
	privkey := new(PrivateKey)

	key := C.EC_KEY_new()
	if key ==nil{
		return nil,errors.New("new eckey error")
	}
	defer C.EC_KEY_free(key)

	//取得c类型 *EC_GROUP
	var group *C.EC_GROUP
	if curveType == 0 {
		privkey.param = GetSM2Test()
		group = C.sm2_ec_group()
	}else if curveType == 1	{
		privkey.param = GetSM2Recom()
		group = C.sm2_ec_group2()
	}
	if group == nil{
		return nil, errors.New("new sm2_group error")
	}
	defer C.EC_GROUP_free(group)
	//取得c类型public key => *EC_POINT
	pub_key := C.EC_POINT_new(group)
	if pub_key == nil{
		return nil, errors.New("new pub_key error")
	}
	defer C.EC_POINT_free(pub_key)
	//将制定的privkey 值放入c 类型key中，到此，c类型 private key取得
	priv_key := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&rnd[0])),
		C.int(len(rnd)), nil)

	if priv_key == nil{
		return nil,errors.New("set priv_key failed")
	}
	defer C.BN_free(priv_key)

	//取得公钥的x 和 y
	pub_key_x := C.BN_new()
	if pub_key_x == nil{
		return nil,errors.New("malloc pub_key_x failed")
	}
	defer C.BN_free(pub_key_x)

	pub_key_y := C.BN_new()
	if pub_key_y == nil{
		return nil,errors.New("malloc pub_key_y failed")
	}
	defer C.BN_free(pub_key_y)

	//计算公钥点
	if C.EC_POINT_mul(group, pub_key, priv_key, nil, nil, nil) == C.int(0) {
		return nil, errors.New("EC_POINT_mul error,get public key point failed")
	}
	//然后将计算出来的各个值取得，并放入到前面new的ECKey中
	// get X and Y coords from pub_key
	if C.EC_POINT_get_affine_coordinates_GFp(group, pub_key, pub_key_x, pub_key_y,
		nil) != C.int(1) {
		return nil, errors.New("EC_POINT_get_affine_coordinates_GFp failed")
	}

	privkey.D = new(big.Int)
	privkey.PublicKey.X = new(big.Int)
	privkey.PublicKey.Y  = new(big.Int)

	privkey_D := make([]byte, C.BN_num_bytes_not_a_macro(priv_key))
	privkey_PublicKey_X := make([]byte, C.BN_num_bytes_not_a_macro(pub_key_x))
	privkey_PublicKey_Y := make([]byte, C.BN_num_bytes_not_a_macro(pub_key_y))
	C.BN_bn2bin(priv_key, (*C.uchar)(unsafe.Pointer(&privkey_D[0])))
	C.BN_bn2bin(pub_key_x, (*C.uchar)(unsafe.Pointer(&privkey_PublicKey_X[0])))
	C.BN_bn2bin(pub_key_y, (*C.uchar)(unsafe.Pointer(&privkey_PublicKey_Y[0])))
	privkey.D.SetBytes(privkey_D)
	privkey.PublicKey.X.SetBytes(privkey_PublicKey_X)
	privkey.PublicKey.Y.SetBytes(privkey_PublicKey_Y)
	return privkey, nil
}

func GeneratePrivKey(curveType int)(*PrivateKey,error){
	rnd,err := randFieldElement(rand.Reader,curveType)
	if err != nil{
		return nil,err
	}
	return GetPrivateKey(rnd,curveType)
}

// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(rand io.Reader,curveType int) ([]byte, error) {
	var param *SM2Param
	if curveType == 0{
		param = GetSM2Test()
	}else if curveType ==1{
		param = GetSM2Recom()
	}else{
		return nil,errors.New("invalid curve type")
	}

	b := make([]byte, 256/8+8)
	_, err := io.ReadFull(rand, b)
	if err != nil {
		return nil,errors.New("read rand failed")
	}

	k := new(big.Int)
	two :=new(big.Int).SetInt64(2)
	one :=new(big.Int).SetInt64(1)
	k = new(big.Int).SetBytes(b)
	N := new(big.Int).SetBytes(param.N)
	n := new(big.Int).Sub(N, two)
	k.Mod(k, n)
	k.Add(k, one)
	return k.Bytes(),nil
}

func ParsePriKeyFromDer(der []byte, curveType int) (*PrivateKey, error) {
	prkInfo := struct {
		Version       int
		PrivateKey    []byte
		NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
		PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
	}{}
	_, err := asn1.Unmarshal(der, &prkInfo)
	if err != nil {
		return nil, err
	}
	return GetPrivateKey(prkInfo.PrivateKey, curveType)
}

func GeneratePublicKey(x []byte,y []byte,curveType int)(retpub *PublicKey,reterr error){
	defer func() { //必须要先声明defer，否则不能捕获到panic异常
		if err := recover(); err != nil {
			reterr = err.(runtime.Error)
		}
	}()
	pubkey := new(PublicKey)
	if curveType ==0 {
		pubkey.param = GetSM2Test()
	}else if curveType == 1{
		pubkey.param = GetSM2Recom()
	}else{
		return nil,errors.New("invalid curve type")
	}
	//取得公钥的x 和 y
	pub_key_x := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&x[0])),
		C.int(len(x)), nil)

	if pub_key_x == nil{
		return nil,errors.New("get pub_key_x failed")
	}
	defer C.BN_free(pub_key_x)
	//取得公钥的x 和 y
	pub_key_y := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&y[0])),
		C.int(len(y)), nil)

	if pub_key_y == nil{
		return nil,errors.New("get pub_key_y failed")
	}
	defer C.BN_free(pub_key_y)
	pubkey.X = new(big.Int)
	pubkey.Y = new(big.Int)

	privkey_PublicKey_X := make([]byte, C.BN_num_bytes_not_a_macro(pub_key_x))
	privkey_PublicKey_Y := make([]byte, C.BN_num_bytes_not_a_macro(pub_key_y))
	C.BN_bn2bin(pub_key_x, (*C.uchar)(unsafe.Pointer(&privkey_PublicKey_X[0])))
	C.BN_bn2bin(pub_key_y, (*C.uchar)(unsafe.Pointer(&privkey_PublicKey_Y[0])))
	pubkey.X.SetBytes(privkey_PublicKey_X)
	pubkey.Y.SetBytes(privkey_PublicKey_Y)
	return pubkey, nil
}

func ParsePubKeyFromDer(der []byte,curveType int) (*PublicKey, error) {
	pukInfo := struct {
		Raw       asn1.RawContent
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{}
	_, err := asn1.Unmarshal(der, &pukInfo)
	//fmt.Printf("OID-> %+v \n",pukInfo)
	if err != nil {
		return nil, err
	}
	raw := pukInfo.PublicKey.Bytes
	if raw[0] != byte(0x04) || len(raw)%2 != 1 {
		return nil, errors.New("public not uncompressed format")
	}
	raw = raw[1:]
	intLength := int(len(raw) / 2)
	keyX := make([]byte, intLength)
	keyY := make([]byte, intLength)
	copy(keyX, raw[:intLength])
	copy(keyY, raw[intLength:])
	return GeneratePublicKey(keyX,keyY,curveType)
}

func TransPubToDer(x []byte,y []byte,curvetype int)([]byte,error){
	pukInfo := struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{}
	pubkey,err := GeneratePublicKey(x,y,curvetype)
	if err != nil{
		return nil,err
	}

	keyX := pubkey.X.Bytes()
	keyY := pubkey.Y.Bytes()
	pubraw := []byte{0x04}
	pubraw = append(pubraw,keyX...)
	pubraw = append(pubraw,keyY...)
	pukInfo.Algorithm.Algorithm = []int{1,2,840,10045,2,1}
	//pukInfo.Algorithm.Parameters = asn1.RawValue {
	//	Class : 0,
	//	IsCompound :true,
	//	Bytes:[]byte{2, 1, 1, 48, 44, 6, 7, 42, 134, 72, 206, 61, 1, 1, 2, 33, 0, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 48, 68, 4, 32, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 252, 4, 32, 40, 233, 250, 158, 157, 159, 94, 52, 77, 90, 158, 75, 207, 101, 9, 167, 243, 151, 137, 245, 21, 171, 143, 146, 221, 188, 189, 65, 77, 148, 14, 147, 4, 65, 4, 50, 196, 174, 44, 31, 25, 129, 25, 95, 153, 4, 70, 106, 57, 201, 148, 143, 227, 11, 191, 242, 102, 11, 225, 113, 90, 69, 137, 51, 76, 116, 199, 188, 55, 54, 162, 244, 246, 119, 156, 89, 189, 206, 227, 107, 105, 33, 83, 208, 169, 135, 124, 198, 42, 71, 64, 2, 223, 50, 229, 33, 57, 240, 160, 2, 33, 0, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 114, 3, 223, 107, 33, 198, 5, 43, 83, 187, 244, 9, 57, 213, 65, 35, 2, 1, 1},
	//	FullBytes:[]byte{48, 129, 224, 2, 1, 1, 48, 44, 6, 7, 42, 134, 72, 206, 61, 1, 1, 2, 33, 0, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 48, 68, 4, 32, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 252, 4, 32, 40, 233, 250, 158, 157, 159, 94, 52, 77, 90, 158, 75, 207, 101, 9, 167, 243, 151, 137, 245, 21, 171, 143, 146, 221, 188, 189, 65, 77, 148, 14, 147, 4, 65, 4, 50, 196, 174, 44, 31, 25, 129, 25, 95, 153, 4, 70, 106, 57, 201, 148, 143, 227, 11, 191, 242, 102, 11, 225, 113, 90, 69, 137, 51, 76, 116, 199, 188, 55, 54, 162, 244, 246, 119, 156, 89, 189, 206, 227, 107, 105, 33, 83, 208, 169, 135, 124, 198, 42, 71, 64, 2, 223, 50, 229, 33, 57, 240, 160, 2, 33, 0, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 114, 3, 223, 107, 33, 198, 5, 43, 83, 187, 244, 9, 57, 213, 65, 35, 2, 1, 1},
	//}
	pukInfo.PublicKey.BitLength = 520
	pukInfo.PublicKey.Bytes = pubraw
	if err != nil {
		return nil, err
	}
	enc, err := asn1.Marshal(pukInfo)
	if err != nil{
		return nil,err
	}
	return enc,nil
}

func ParseSignToRS(asn1DerSign []byte,curvetype int)(r *big.Int,s *big.Int,err error){
	sign := struct {
		R,S *big.Int
	}{}
	_,err = asn1.Unmarshal(asn1DerSign,&sign)
	if err != nil{
		return
	}
	r = sign.R
	s = sign.S
	return
}

func TransSignToDer(r *big.Int,s *big.Int,curvetype int)([]byte,error){
	sign := struct {
		R,S *big.Int
	}{}
	sign.R = r;
	sign.S = s;
	return asn1.Marshal(sign)
}

func ParsePubKeyFromEncode(der []byte,curveType int) (*PublicKey, error) {
	raw := der
	if raw[0] != byte(0x04) || len(raw)%2 != 1 {
		return nil, errors.New("public key not uncompressed format, please check your public key format.")
	}
	raw = raw[1:]
	intLength := int(len(raw) / 2)
	key_X := make([]byte, intLength)
	key_Y := make([]byte, intLength)
	copy(key_X, raw[:intLength])
	copy(key_Y, raw[intLength:])
	return GeneratePublicKey(key_X,key_Y,curveType)
}

func (prikey *PrivateKey) Sign(msg []byte) ([]byte, error) {
	dgst := prikey.PublicKey.PreHandle(msg)
	ec_key, err := prikey.getEC_KEY()
	if err != nil{
		return nil, err
	}
	defer C.EC_KEY_free(ec_key)
	//sig :=  (*C.uchar)(C.malloc(256))
	sigLen := C.uint(256)
	sig := make([]byte, 256)
	pid := C.SM2_sign(C.NID_undef, (*C.uchar)(unsafe.Pointer(&dgst[0])), C.int(len(dgst)), (*C.uchar)(unsafe.Pointer(&sig[0])), &sigLen, ec_key)
	if pid == 1 {
		sig = sig[:sigLen]
	}
	count := 0
	bol := false
	bol,_ = prikey.PublicKey.Verify(sig,msg);
	for{
		if count >100{
			return nil, errors.New("Sign failed,times out")
		}
		bol,_ = prikey.PublicKey.Verify(sig,msg);
		if !bol{
			pid = C.SM2_sign(C.NID_undef, (*C.uchar)(unsafe.Pointer(&dgst[0])), C.int(len(dgst)), (*C.uchar)(unsafe.Pointer(&sig[0])), &sigLen, ec_key)
			if pid == 1 {
				sig = sig[:sigLen]
			}else{
				return nil, errors.New("Sign failed, internal error")
			}
		}else{
			return sig,nil
		}
		fmt.Println(count)
		count ++
	}
	return sig,nil

}

func (priv *PrivateKey)getEC_KEY()(*C.EC_KEY,error){
	ctype := priv.param.CurveType
	ec_key := C.EC_KEY_new()
	privD := priv.D.Bytes()
	//fmt.Println(privD)
	pubX := priv.PublicKey.X.Bytes()
	pubY := priv.PublicKey.Y.Bytes()
	//err := C.GetECKeyPrivate(ec_key,privD,pubX,pubY,C.int(ctype))
	err := C.GetECKeyPrivate(ec_key,(*C.uchar)(unsafe.Pointer(&privD[0])),C.int(len(privD)),(*C.uchar)(unsafe.Pointer(&pubX[0])),C.int(len(pubX)), (*C.uchar)(unsafe.Pointer(&pubY[0])),C.int(len(pubY)),C.int(ctype))
	if int(err) != 0{
		return nil,errors.New(fmt.Sprintf("error code: %d",int(err)))
	}
	return ec_key,nil
}

func (pub *PublicKey)getEC_KEY()(*C.EC_KEY,error){
	ctype := pub.param.CurveType
	ec_key := C.EC_KEY_new()
	pubX :=pub.X.Bytes();
	pubY := pub.Y.Bytes();
	err := C.GetECKeyPublic(ec_key,(*C.uchar)(unsafe.Pointer(&pubX[0])),C.int(len(pubX)), (*C.uchar)(unsafe.Pointer(&pubY[0])),C.int(len(pubY)),C.int(ctype))
	if int(err) != 0{
		return nil,errors.New(fmt.Sprintf("error code: %d",int(err)))
	}
	return ec_key,nil
}

func (pubkey *PublicKey) Verify(sig, msg []byte) (f bool,reterr error) {
	defer func() { //必须要先声明defer，否则不能捕获到panic异常
		if err := recover(); err != nil {
			reterr = err.(runtime.Error)
		}
	}()
	ec_key, err := pubkey.getEC_KEY()
	dgst := pubkey.PreHandle(msg)
	//fmt.Println("Za :",common.Bytes2Hex(dgst))
	if err != nil {
		return false, err
	}
	defer C.EC_KEY_free(ec_key)
	bol := C.SM2_verify(C.NID_undef, (*C.uchar)(unsafe.Pointer(&dgst[0])), C.int(len(dgst)), (*C.uchar)(unsafe.Pointer(&sig[0])), C.int(len(sig)), ec_key)
	if bol == 1 {
		return true, nil
	}
	return false, errors.New("invaild signature!")
}

func (pubkey *PublicKey)PreHandle(msg []byte)[]byte{
	return pubkey.param.preHandle(msg,pubkey)
}

func (pubkey *PublicKey)Check()(bool,error){
	ec_key,err := pubkey.getEC_KEY()
	if err != nil{
		return false,err
	}
	// validate the key
	if C.EC_KEY_check_key(ec_key) != C.int(1) {
		return false, errors.New("EC_KEY_check_key failed")
	}
	return true,nil
}

