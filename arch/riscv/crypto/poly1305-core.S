#if __riscv_xlen == 64
# if __SIZEOF_POINTER__ == 16
#  define PUSH	csc
#  define POP	clc
# else
#  define PUSH	sd
#  define POP	ld
# endif
#else
# error "unsupported __riscv_xlen"
#endif

.option	pic
.text

.globl	poly1305_init_riscv
.type	poly1305_init_riscv,@function
poly1305_init_riscv:
	sd	x0,0(x10)
	sd	x0,8(x10)
	sd	x0,16(x10)

	beqz	x11,.Lno_key

#ifndef	__CHERI_PURE_CAPABILITY__
	andi	x16,x11,7		# x11 % 8
	andi	x11,x11,-8		# align x11
	slli	x16,x16,3		# byte to bit offset
#endif
	ld	x14,0(x11)
	ld	x15,8(x11)
#ifndef	__CHERI_PURE_CAPABILITY__
	beqz	x16,.Laligned_key

	ld	x5,16(x11)
	neg	x17,x16		# implicit &63 in sll
	srl	x14,x14,x16
	sll	x6,x15,x17
	srl	x15,x15,x16
	sll	x5,x5,x17
	or	x14,x14,x6
	or	x15,x15,x5

.Laligned_key:
#endif
	li	x16,1
	slli	x16,x16,32		# 0x0000000100000000
	addi	x16,x16,-63		# 0x00000000ffffffc1
	slli	x16,x16,28		# 0x0ffffffc10000000
	addi	x16,x16,-1		# 0x0ffffffc0fffffff

	and	x14,x14,x16
	addi	x16,x16,-3		# 0x0ffffffc0ffffffc
	and	x15,x15,x16

	sd	x14,24(x10)
	srli	x16,x15,2
	sd	x15,32(x10)
	add	x16,x16,x15	# s1 = r1 + (r1 >> 2)
	sd	x16,40(x10)

.Lno_key:
	li	x10,0			# return 0
	ret
.size	poly1305_init_riscv,.-poly1305_init_riscv
.globl	poly1305_blocks_riscv
.type	poly1305_blocks_riscv,@function
poly1305_blocks_riscv:
	andi	x12,x12,-16		# complete blocks only
	beqz	x12,.Lno_data

	add	x2,x2,-4*__SIZEOF_POINTER__
	PUSH	x8,3*__SIZEOF_POINTER__(x2)
	PUSH	x9,2*__SIZEOF_POINTER__(x2)
	PUSH	x18,1*__SIZEOF_POINTER__(x2)
	PUSH	x19,0*__SIZEOF_POINTER__(x2)

#ifndef	__CHERI_PURE_CAPABILITY__
	andi	x30,x11,7
	andi	x11,x11,-8		# align x11
	slli	x30,x30,3		# byte to bit offset
	neg	x31,x30		# implicit &63 in sll
#endif

	ld	x8,0(x10)		# load hash value
	ld	x9,8(x10)
	ld	x18,16(x10)

	ld	x19,24(x10)		# load key
	ld	x28,32(x10)
	ld	x29,40(x10)

	add	x12,x12,x11		# end of buffer

.Loop:
	ld	x14,0(x11)		# load input
	ld	x15,8(x11)
#ifndef	__CHERI_PURE_CAPABILITY__
	beqz	x30,.Laligned_inp

	ld	x5,16(x11)
	srl	x14,x14,x30
	sll	x6,x15,x31
	srl	x15,x15,x30
	sll	x5,x5,x31
	or	x14,x14,x6
	or	x15,x15,x5

.Laligned_inp:
#endif
	add	x11,x11,16

	andi	x16,x18,-4		# modulo-scheduled reduction
	srli	x17,x18,2
	andi	x18,x18,3

	add	x14,x8,x14		# accumulate input
	 add	x17,x17,x16
	sltu	x16,x14,x8
	add	x14,x14,x17		# ... and residue
	sltu	x17,x14,x17
	add	x15,x9,x15
	add	x16,x16,x17
	sltu	x17,x15,x9
	add	x15,x15,x16

	 add	x7,x18,x13
	 sltu	x16,x15,x16
	mulhu	x9,x19,x14		# h0*r0
	mul	x8,x19,x14

	 add	x7,x7,x17
	 add	x7,x7,x16
	mulhu	x17,x29,x15		# h1*5*r1
	mul	x16,x29,x15

	mulhu	x18,x28,x14		# h0*r1
	mul	x5,x28,x14
	 add	x8,x8,x16
	 add	x9,x9,x17
	 sltu	x16,x8,x16

	 add	x9,x9,x16
	 add	x9,x9,x5
	mulhu	x17,x19,x15		# h1*r0
	mul	x16,x19,x15

	 sltu	x5,x9,x5
	 add	x18,x18,x5
	mul	x5,x29,x7		# h2*5*r1

	 add	x9,x9,x16
	 add	x18,x18,x17
	mul	x6,x19,x7		# h2*r0
	 sltu	x16,x9,x16
	 add	x18,x18,x16

	add	x9,x9,x5
	sltu	x5,x9,x5
	add	x18,x18,x5
	add	x18,x18,x6

	bne	x11,x12,.Loop

	sd	x8,0(x10)		# store hash value
	sd	x9,8(x10)
	sd	x18,16(x10)

	POP	x8,3*__SIZEOF_POINTER__(x2)		# epilogue
	POP	x9,2*__SIZEOF_POINTER__(x2)
	POP	x18,1*__SIZEOF_POINTER__(x2)
	POP	x19,0*__SIZEOF_POINTER__(x2)
	add	x2,x2,4*__SIZEOF_POINTER__

.Lno_data:
	ret
.size	poly1305_blocks_riscv,.-poly1305_blocks_riscv
.globl	poly1305_emit_riscv
.type	poly1305_emit_riscv,@function
poly1305_emit_riscv:
	ld	x5,16(x10)
	ld	x16,0(x10)
	ld	x17,8(x10)

	andi	x14,x5,-4		# final reduction
	srl	x15,x5,2
	andi	x5,x5,3
	add	x14,x14,x15

	add	x16,x16,x14
	sltu	x15,x16,x14
	 addi	x14,x16,5		# compare to modulus
	add	x17,x17,x15
	 sltiu	x6,x14,5
	sltu	x7,x17,x15
	 add	x15,x17,x6
	add	x5,x5,x7
	 sltu	x6,x15,x6
	 add	x5,x5,x6

	srli	x5,x5,2		# see if it carried/borrowed
	neg	x5,x5

	xor	x14,x14,x16
	xor	x15,x15,x17
	and	x14,x14,x5
	and	x15,x15,x5
	xor	x14,x14,x16
	xor	x15,x15,x17

	lwu	x16,0(x12)		# load nonce
	lwu	x17,4(x12)
	lwu	x5,8(x12)
	lwu	x6,12(x12)
	slli	x17,x17,32
	slli	x6,x6,32
	or	x16,x16,x17
	or	x5,x5,x6

	add	x14,x14,x16		# accumulate nonce
	add	x15,x15,x5
	sltu	x16,x14,x16
	add	x15,x15,x16

	srli	x16,x14,8		# write mac value
	srli	x17,x14,16
	srli	x5,x14,24
	sb	x14,0(x11)
	srli	x6,x14,32
	sb	x16,1(x11)
	srli	x16,x14,40
	sb	x17,2(x11)
	srli	x17,x14,48
	sb	x5,3(x11)
	srli	x5,x14,56
	sb	x6,4(x11)
	srli	x6,x15,8
	sb	x16,5(x11)
	srli	x16,x15,16
	sb	x17,6(x11)
	srli	x17,x15,24
	sb	x5,7(x11)

	sb	x15,8(x11)
	srli	x5,x15,32
	sb	x6,9(x11)
	srli	x6,x15,40
	sb	x16,10(x11)
	srli	x16,x15,48
	sb	x17,11(x11)
	srli	x17,x15,56
	sb	x5,12(x11)
	sb	x6,13(x11)
	sb	x16,14(x11)
	sb	x17,15(x11)

	ret
.size	poly1305_emit_riscv,.-poly1305_emit_riscv
.string	"Poly1305 for RISC-V, CRYPTOGAMS by @dot-asm"
