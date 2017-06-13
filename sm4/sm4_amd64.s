// func SHL(x [4]byte) [4]byte
// SHL(x,n) (((x) & 0xFFFFFFFF) << n)
TEXT ·SHL(SB),0,$0-24
    MOVQ x+0(FP), AX
    ANDQ $0xFFFFFFFF,AX
    MOVQ n+8(FP), CX
    SHLQ CX,AX
    MOVQ AX, ret+16(FP)
    RET

TEXT ·SHR(SB),0,$0
    MOVQ x+0(FP), AX
    ANDQ $0xFFFFFFFF,AX
    MOVQ n+8(FP), CX
    SHRQ CX,AX
    MOVQ AX, ret+16(FP)
    RET

TEXT ·SUB(SB),0,$0-9
     MOVQ a+0(FP), AX
     MOVQ b+1(FP), BX
     // BX 1, AX 2 -> AX
     SUBQ BX,AX
     MOVQ AX,ret+8(FP)
     RET


//func XOR(a [4]byte, b [4]byte) [4]byte

TEXT ·XOR(SB),0,$0
    MOVQ a+0(FP),AX
    MOVQ b+4(FP),BX
    XORQ AX,BX
    MOVQ BX,ret+8(FP)
    RET

// func ROTL(x [4]byte,n int)[4] byte
// ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))
TEXT ·ROTLA(SB),0,$0
    // circle shl implements
    // 0111 << 3  <=> 1011
    // rotl:
    // x << 3 | x >> ( 4 -3 )
    // 0111 << 3  | 0111 >> 1
    // 1000 | 0011
    // 1011

    // SHL PART
    MOVL x+0(FP), AX
    MOVL x+0(FP), R8
    ANDQ $0xFFFFFFFF,AX

    // Here need BigEndian to Little Endian
    // BigEndian to littleEndian
    MOVQ AX,R9
    ANDQ $0x000000FF,R9
    MOVQ $24,CX
    SHLQ CX,R9
    MOVQ AX,R10
    ANDQ $0x0000FF00,R10
    MOVQ $8,CX
    SHLQ CX,R10
    MOVQ AX,R11
    ANDQ $0x00FF0000,R11
    MOVQ $8,CX
    SARQ CX,R11
    MOVQ AX,R12
    ANDQ $0xFF000000,R12
    MOVQ $24,CX
    SARQ CX,R12
    ORQ R9,R10
    ORQ R10,R11
    ORQ R11,R12
    // SHL(x,n)
    MOVQ n+8(FP),CX
    SHLQ CX,R12
    MOVQ R12,R8



    // Little Endian to Big Endian
    MOVQ R8,R9
    ANDQ $0x000000FF,R9
    MOVQ $24,CX
    SHLQ CX,R9

    MOVQ R8,R10
    ANDQ $0x0000FF00,R10
    MOVQ $8,CX
    SHLQ CX,R10


    MOVQ R8,R11
    ANDQ $0x00FF0000,R11
    MOVQ $8,CX
    SARQ CX,R11

    MOVQ R8,R12
    ANDQ $0x7F000000,R12

    MOVQ $24,CX
    SARQ CX,R12
    // DEBUG
    MOVQ R12,R14

    ORQ R9,R10
    ORQ R10,R11
    ORQ R11,R12



    // Save Step 1.result
    MOVQ R12,R15

    // x >> (32 -n)
    // Here should be shift algorithm  right
    // here has a trap
    // Example:
    // actual input data is : 0x00000001
    // data   : 00000000 00000000 00000000 00000001
    // SARQ data , $1
    // result : 00000000 00000000 10000000 00000000
    // so here need to reorder the data
    // BigEndian to littleEndian
    MOVQ R8,R9
    ANDQ $0x000000FF,R9
    MOVQ $24,CX
    SHLQ CX,R9

    MOVQ R8,R10
    ANDQ $0x0000FF00,R10
    MOVQ $8,CX
    SHLQ CX,R10

    MOVQ R8,R11
    ANDQ $0x00FF0000,R11
    MOVQ $8,CX
    SARQ CX,R11

    MOVQ R8,R12
    ANDQ $0xFF000000,R12
    MOVQ $24,CX
    SARQ CX,R12

    ORQ R9,R10
    ORQ R10,R11
    ORQ R11,R12
    //DEBUG
    //MOVQ R12,R14

    // SHRQ
    // SUB PART
    MOVQ x+8(FP),DX
    // CX = 32  DX = n
    MOVQ $32,CX

    // CX = 32 - n
    SUBQ DX,CX

    SARQ CX,R12

    MOVQ R12,R8
    //DEBUG
    //MOVQ R12,R14
    //LittleEndian to BigEndian
    MOVQ R8,R9
    ANDQ $0x000000FF,R9
    MOVQ $24,CX
    SHLQ CX,R9

    MOVQ R8,R10
    ANDQ $0x0000FF00,R10
    MOVQ $8,CX
    SHLQ CX,R10

    MOVQ R8,R11
    ANDQ $0x00FF0000,R11
    MOVQ $8,CX
    SARQ CX,R11

    MOVQ R8,R12
    ANDQ $0xFF000000,R12
    MOVQ $24,CX
    SARQ CX,R12

    ORQ R9,R10
    ORQ R10,R11
    ORQ R11,R12
    //DEBUG
    //MOVQ R15,R14

    // XOR
    // (SHL((x),n) | ((x) >> (32 - n)))
    ORQ R12,R15

    MOVQ R14, ret+16(FP)
    RET



TEXT ·TEST(SB),0,$0
    MOVQ x+0(FP),AX
    ANDQ $0x00000000,AX
    MOVQ AX,ret+8(FP)
    RET
