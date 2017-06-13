package sm3

/*
#cgo CFLAGS : -I./include -I/usr/local/include -I/usr/include
#cgo LDFLAGS: -L/usr/local/lib -L/usr/lib -L/usr/lib -lssl -lcrypto
#include <stdlib.h>
#include "./libsm3/sm3.h"
#include "./libsm3/sm3.c"
*/
import "C"

import (
	"hash"
	"unsafe"
)

/**
sm3_hash
this context implements the hash.Hash interface
*/
type sm3ctx struct {
	ctx C.sm3_ctx_t
}

//SM3New return a hasher for sm3 algorithm
func SM3New() hash.Hash {
	h := new(sm3ctx)
	C.sm3_init(&h.ctx)
	return h
}

func clone(src *sm3ctx) *sm3ctx {
	sm3 := new(sm3ctx)
	sm3.ctx = src.ctx
	return sm3
}

//Write the same as hash write
func (ctx *sm3ctx) Write(msg []byte) (n int, err error) {
	size := C.size_t(len(msg))
	val := (*C.uchar)(unsafe.Pointer(C.CString(string(msg))))
	defer C.free(unsafe.Pointer(val))
	C.sm3_update(&ctx.ctx, val, size)
	return len(msg), nil
}

//Sum the same as hash sum
func (ctx *sm3ctx) Sum(b []byte) []byte {
	buf := make([]C.uchar, ctx.Size())
	ctxTmp := clone(ctx)
	C.sm3_final(&ctxTmp.ctx, &buf[0])
	var result []byte
	if b != nil {
		result = make([]byte, 0)
	} else {
		result = b
	}
	for _, value := range buf {
		result = append(result, byte(value))
	}
	return result
}

//Reset the same as hash Reset
func (ctx *sm3ctx) Reset() {
	C.sm3_init(&ctx.ctx)
}

//Size hash size
func (ctx *sm3ctx) Size() int {
	return C.SM3_DIGEST_LENGTH
}

//Block hash Blocsize
func (ctx *sm3ctx) BlockSize() int {
	return C.SM3_BLOCK_SIZE
}
