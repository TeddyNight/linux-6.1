// SPDX-License-Identifier: GPL-2.0-only
/*
 * ChaCha20 using the RISC-V vector crypto extensions
 *
 * Copyright (C) 2023 SiFive, Inc.
 * Author: Jerry Shih <jerry.shih@sifive.com>
 */

#include <asm/simd.h>
#include <asm/vector.h>
#include <crypto/internal/chacha.h>
#include <crypto/internal/skcipher.h>
#include <linux/linkage.h>
#include <linux/module.h>

asmlinkage void chacha20_zvkb(const u32 key[8], const u8 *in, u8 *out,
			      size_t len, const u32 iv[4]);
asmlinkage void chacha20_v(const u32 key[8], const u8 *in, u8 *out,
			      size_t len, const u32 iv[4]);

static void do_chacha20_v(u32 *state, const u8 *src, u8 *dst,
		              int bytes)
{
	u8 block_buffer[CHACHA_BLOCK_SIZE];
	unsigned int nbytes;
	unsigned int tail_bytes;
	while (bytes > 0) {
		int l = min(bytes, CHACHA_BLOCK_SIZE * 4);
		nbytes = l & ~(CHACHA_BLOCK_SIZE - 1);
		tail_bytes = l & (CHACHA_BLOCK_SIZE - 1);
		kernel_vector_begin();
		if (nbytes) {
			chacha20_v(&state[4], src, dst,
				   nbytes, &state[12]);
			state[12] += nbytes / CHACHA_BLOCK_SIZE;
		}
		if (l == bytes && tail_bytes > 0) {
			memcpy(block_buffer, src,
			       tail_bytes);
			chacha20_v(&state[4], block_buffer, block_buffer,
			           CHACHA_BLOCK_SIZE, &state[12]);
			memcpy(dst, block_buffer,
			       tail_bytes);
		}
		kernel_vector_end();
		bytes -= l;
		src += l;
		dst += l;
	}
}

static void do_chacha20_zvkb(u32 *state, const u8 *src, u8 *dst,
		              int bytes)
{
	u8 block_buffer[CHACHA_BLOCK_SIZE];
	unsigned int nbytes;
	unsigned int tail_bytes;
	while (bytes > 0) {
		int l = min(bytes, CHACHA_BLOCK_SIZE * 4);
		nbytes = l & ~(CHACHA_BLOCK_SIZE - 1);
		tail_bytes = l & (CHACHA_BLOCK_SIZE - 1);
		kernel_vector_begin();
		if (nbytes) {
			chacha20_zvkb(&state[4], src, dst,
				   nbytes, &state[12]);
			state[12] += nbytes / CHACHA_BLOCK_SIZE;
		}
		if (l == bytes && tail_bytes > 0) {
			memcpy(block_buffer, src,
			       tail_bytes);
			chacha20_zvkb(&state[4], block_buffer, block_buffer,
			           CHACHA_BLOCK_SIZE, &state[12]);
			memcpy(dst, block_buffer,
			       tail_bytes);
		}
		kernel_vector_end();
		bytes -= l;
		src += l;
		dst += l;
	}
}

static int riscv64_chacha20_zvkb_crypt(struct skcipher_request *req)
{
	u32 iv[CHACHA_IV_SIZE / sizeof(u32)];
	u8 block_buffer[CHACHA_BLOCK_SIZE];
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct chacha_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	unsigned int tail_bytes;
	int err;

	iv[0] = get_unaligned_le32(req->iv);
	iv[1] = get_unaligned_le32(req->iv + 4);
	iv[2] = get_unaligned_le32(req->iv + 8);
	iv[3] = get_unaligned_le32(req->iv + 12);

	err = skcipher_walk_virt(&walk, req, false);
	while (walk.nbytes) {
		nbytes = walk.nbytes & ~(CHACHA_BLOCK_SIZE - 1);
		tail_bytes = walk.nbytes & (CHACHA_BLOCK_SIZE - 1);
		kernel_vector_begin();
		if (nbytes) {
			chacha20_zvkb(ctx->key, walk.src.virt.addr,
				      walk.dst.virt.addr, nbytes, iv);
			iv[0] += nbytes / CHACHA_BLOCK_SIZE;
		}
		if (walk.nbytes == walk.total && tail_bytes > 0) {
			memcpy(block_buffer, walk.src.virt.addr + nbytes,
			       tail_bytes);
			chacha20_zvkb(ctx->key, block_buffer, block_buffer,
				      CHACHA_BLOCK_SIZE, iv);
			memcpy(walk.dst.virt.addr + nbytes, block_buffer,
			       tail_bytes);
			tail_bytes = 0;
		}
		kernel_vector_end();

		err = skcipher_walk_done(&walk, tail_bytes);
	}

	return err;
}

static int riscv64_chacha20_v_crypt(struct skcipher_request *req)
{
	u32 iv[CHACHA_IV_SIZE / sizeof(u32)];
	u8 block_buffer[CHACHA_BLOCK_SIZE];
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	const struct chacha_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	unsigned int nbytes;
	unsigned int tail_bytes;
	int err;

	iv[0] = get_unaligned_le32(req->iv);
	iv[1] = get_unaligned_le32(req->iv + 4);
	iv[2] = get_unaligned_le32(req->iv + 8);
	iv[3] = get_unaligned_le32(req->iv + 12);

	err = skcipher_walk_virt(&walk, req, false);
	while (walk.nbytes) {
		nbytes = walk.nbytes & ~(CHACHA_BLOCK_SIZE - 1);
		tail_bytes = walk.nbytes & (CHACHA_BLOCK_SIZE - 1);
		kernel_vector_begin();
		if (nbytes) {
			chacha20_v(ctx->key, walk.src.virt.addr,
				      walk.dst.virt.addr, nbytes, iv);
			iv[0] += nbytes / CHACHA_BLOCK_SIZE;
		}
		if (walk.nbytes == walk.total && tail_bytes > 0) {
			memcpy(block_buffer, walk.src.virt.addr + nbytes,
			       tail_bytes);
			chacha20_v(ctx->key, block_buffer, block_buffer,
				      CHACHA_BLOCK_SIZE, iv);
			memcpy(walk.dst.virt.addr + nbytes, block_buffer,
			       tail_bytes);
			tail_bytes = 0;
		}
		kernel_vector_end();

		err = skcipher_walk_done(&walk, tail_bytes);
	}

	return err;
}

static struct skcipher_alg riscv64_zvkb_chacha_alg = {
	.setkey = chacha20_setkey,
	.encrypt = riscv64_chacha20_zvkb_crypt,
	.decrypt = riscv64_chacha20_zvkb_crypt,
	.min_keysize = CHACHA_KEY_SIZE,
	.max_keysize = CHACHA_KEY_SIZE,
	.ivsize = CHACHA_IV_SIZE,
	.chunksize = CHACHA_BLOCK_SIZE,
	.walksize = 4 * CHACHA_BLOCK_SIZE,
	.base = {
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct chacha_ctx),
		.cra_priority = 300,
		.cra_name = "chacha20",
		.cra_driver_name = "chacha20-riscv64-zvkb",
		.cra_module = THIS_MODULE,
	},
};

static struct skcipher_alg riscv64_v_chacha_alg = {
	.setkey = chacha20_setkey,
	.encrypt = riscv64_chacha20_v_crypt,
	.decrypt = riscv64_chacha20_v_crypt,
	.min_keysize = CHACHA_KEY_SIZE,
	.max_keysize = CHACHA_KEY_SIZE,
	.ivsize = CHACHA_IV_SIZE,
	.chunksize = CHACHA_BLOCK_SIZE,
	.walksize = 4 * CHACHA_BLOCK_SIZE,
	.base = {
		.cra_blocksize = 1,
		.cra_ctxsize = sizeof(struct chacha_ctx),
		.cra_priority = 300,
		.cra_name = "chacha20",
		.cra_driver_name = "chacha20-riscv64-v",
		.cra_module = THIS_MODULE,
	},
};

void hchacha_block_arch(const u32 *state, u32 *stream, int nrounds)
{
	hchacha_block_generic(state, stream, nrounds);
}
EXPORT_SYMBOL(hchacha_block_arch);

void chacha_init_arch(u32 *state, const u32 *key, const u8 *iv)
{
	chacha_init_generic(state, key, iv);
}
EXPORT_SYMBOL(chacha_init_arch);

void chacha_crypt_arch(u32 *state, u8 *dst, const u8 *src,
		       unsigned int bytes, int nrounds)
{
	// riscv64 chacha20 implementation has 20 rounds hard-coded
	if (riscv_vector_vlen() < 128 || nrounds != 20)
		return chacha_crypt_generic(state, dst, src, bytes, nrounds);

	if (riscv_isa_extension_available(NULL, ZVKB))
		return do_chacha20_zvkb(state, src, dst, bytes);
	return do_chacha20_v(state, src, dst, bytes);
}
EXPORT_SYMBOL(chacha_crypt_arch);

static int __init riscv64_chacha_mod_init(void)
{
	if (riscv_vector_vlen() >= 128) {
		if (riscv_isa_extension_available(NULL, ZVKB))
			return crypto_register_skcipher(&riscv64_zvkb_chacha_alg);
		return crypto_register_skcipher(&riscv64_v_chacha_alg);
	}

	return -ENODEV;
}

static void __exit riscv64_chacha_mod_exit(void)
{
	if (riscv_isa_extension_available(NULL, ZVKB))
		crypto_unregister_skcipher(&riscv64_zvkb_chacha_alg);
	crypto_unregister_skcipher(&riscv64_v_chacha_alg);
}

module_init(riscv64_chacha_mod_init);
module_exit(riscv64_chacha_mod_exit);

MODULE_DESCRIPTION("ChaCha20 (RISC-V accelerated)");
MODULE_AUTHOR("Jerry Shih <jerry.shih@sifive.com>");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CRYPTO("chacha20");
