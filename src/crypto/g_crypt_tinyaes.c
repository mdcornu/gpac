/*
*			GPAC - Multimedia Framework C SDK
*
*			Authors: Jean Le Feuvre
*			Copyright (c) Telecom ParisTech 2018
*					All rights reserved
*
*  This file is part of GPAC / crypto lib sub-project
*
*  GPAC is free software; you can redistribute it and/or modify
*  it under the terms of the GNU Lesser General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.
*
*  GPAC is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU Lesser General Public License for more details.
*
*  You should have received a copy of the GNU Lesser General Public
*  License along with this library; see the file COPYING.  If not, write to
*  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*/

#include <gpac/internal/crypt_dev.h>

#ifndef GPAC_HAS_SSL
#include "tiny_aes.h"

#include <math.h>
#include <intel-ipsec-mb.h>

/** CBC mode **/

GF_Err gf_crypt_init_tinyaes_cbc(GF_Crypt* td, void *key, const void *iv)
{
	struct AES_ctx *ctx = (struct AES_ctx *)td->context;
	IMB_MGR *p_mgr = NULL;
	u64 flags = 0;
	int err;

	if (!ctx) {
		GF_SAFEALLOC(ctx, struct AES_ctx);
		if (ctx == NULL) return GF_OUT_OF_MEM;

		td->context = ctx;
	}

	if (iv != NULL) {
		AES_init_ctx_iv(ctx, key, iv);
	} else {
		AES_init_ctx(ctx, key);
	}

	/* allocate multi-buffer manager */
	p_mgr = alloc_mb_mgr(flags);
	if (p_mgr == NULL) {
		return GF_NOT_FOUND;
	}
	td->imb_mgr = (void *)p_mgr;

	/* initialize mb_mgr */
	init_mb_mgr_auto(p_mgr, NULL);
	err = imb_get_errno(p_mgr);
	if (err != 0) {
		printf("IMB init error: %s!\n", imb_get_strerror(err));
		return GF_NOT_FOUND;
	}

	/* expand aes-128 key */
	IMB_AES_KEYEXP_128(p_mgr, key, ctx->enc_keys, ctx->dec_keys);

	return GF_OK;
}

void gf_crypt_deinit_tinyaes_cbc(GF_Crypt* td)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	IMB_MGR *p_mgr = (IMB_MGR *)td->imb_mgr;

	free_mb_mgr(p_mgr);
}

void gf_set_key_tinyaes_cbc(GF_Crypt* td, void *key)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	AES_init_ctx(ctx, key);
}

GF_Err gf_crypt_set_IV_tinyaes_cbc(GF_Crypt* td, const u8 *iv, u32 iv_size)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	if (iv_size>AES_BLOCKLEN) return GF_BAD_PARAM;

	AES_ctx_set_iv(ctx, iv);
	return GF_OK;
}

GF_Err gf_crypt_get_IV_tinyaes_cbc(GF_Crypt* td, u8 *iv, u32 *iv_size)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	AES_ctx_get_iv(ctx, iv);
	*iv_size = AES_BLOCKLEN;

	return GF_OK;
}


GF_Err gf_crypt_encrypt_tinyaes_cbc(GF_Crypt* td, u8 *plaintext, u32 len)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	AES_CBC_encrypt_buffer(ctx, plaintext, len);
	return GF_OK;
}

GF_Err gf_crypt_decrypt_tinyaes_cbc(GF_Crypt* td, u8 *ciphertext, u32 len)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	if (len<AES_BLOCKLEN) return GF_OK;
	while (len % AES_BLOCKLEN)
		len--;
	AES_CBC_decrypt_buffer(ctx, ciphertext, len);
	return GF_OK;
}

GF_Err gf_crypt_encrypt_enqueue_ipsec_mb_cbcs(GF_Crypt *td, u8 *plaintext,
                                              u32 len, void** pck)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	IMB_MGR *p_mgr = (IMB_MGR *)td->imb_mgr;
	IMB_JOB *job = NULL;
	GF_Err e;
	const u64 align16_mask = ~0xf;

	job = IMB_GET_NEXT_JOB(p_mgr);
	job->cipher_direction = IMB_DIR_ENCRYPT;
	job->chain_order = IMB_ORDER_CIPHER_HASH;
	job->dst = plaintext;
	job->src = plaintext;
	job->cipher_mode = IMB_CIPHER_CBCS_1_9;
	job->enc_keys = ctx->enc_keys;
	job->dec_keys = ctx->dec_keys;
	job->key_len_in_bytes = 16;
	job->iv = (u8 *)ctx->Iv;
	job->iv_len_in_bytes = 16;
	job->cipher_start_src_offset_in_bytes = 0;
	job->msg_len_to_cipher_in_bytes = len & align16_mask;
	job->hash_alg = IMB_AUTH_NULL;
	job->cipher_fields.CBCS.next_iv = (u8 *)ctx->Iv;

	// keep refs to in / out packets
	job->user_data = *pck;

	// submit job to be processed
	job = IMB_SUBMIT_JOB(p_mgr);
	if (job != NULL) {
		// if job returned then set out packet pointer
		*pck = job->user_data;
	} else {
		// otherwise set to NULL
		*pck = NULL;

		int err = imb_get_errno(p_mgr);
		if (err != 0) {
			printf("IMB Error: %s!\n", imb_get_strerror(err));
			return GF_NOT_FOUND;
		}
	}
	return GF_OK;
}

void * gf_crypt_get_completed_ipsec_mb_cbcs(GF_Crypt *td)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	IMB_MGR *p_mgr = (IMB_MGR *)td->imb_mgr;
	IMB_JOB *job = NULL;

	job = IMB_GET_COMPLETED_JOB(p_mgr);
	if (job != NULL) {
		// if job returned then return packet
		return job->user_data;
	} else {
		// otherwise set to NULL
		int err = imb_get_errno(p_mgr);
		if (err != 0)
			printf("IMB Error: %s!\n", imb_get_strerror(err));

		return NULL;
	}
}

void * gf_crypt_flush_ipsec_mb_cbcs(GF_Crypt *td)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	IMB_MGR *p_mgr = (IMB_MGR *)td->imb_mgr;
	IMB_JOB *job = NULL;

	job = IMB_FLUSH_JOB(p_mgr);
	if (job != NULL) {
		// if job returned then set packet
		return job->user_data;
	} else {
		// otherwise set to NULL
		int err = imb_get_errno(p_mgr);
		if (err != 0)
			printf("IMB Error: %s!\n", imb_get_strerror(err));

		return NULL;
	}
}

/** CTR mode **/

void gf_set_key_tinyaes_ctr(GF_Crypt* td, void *key)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	AES_init_ctx(ctx, key);
}

GF_Err gf_crypt_set_IV_tinyaes_ctr(GF_Crypt* td, const u8 *iv, u32 iv_size)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;

	if (iv_size>AES_BLOCKLEN) {
		ctx->counter_pos = iv[0];
		AES_ctx_set_iv(ctx, &((u8*)iv)[1]);
	} else {
		AES_ctx_set_iv(ctx, iv);
	}
	return GF_OK;
}

GF_Err gf_crypt_get_IV_tinyaes_ctr(GF_Crypt* td, u8 *iv, u32 *iv_size)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	*iv_size = AES_BLOCKLEN + 1;
	iv[0] = ctx->counter_pos;
	AES_ctx_get_iv(ctx, iv + 1);
	return GF_OK;
}

GF_Err gf_crypt_init_tinyaes_ctr(GF_Crypt* td, void *key, const void *iv)
{
	struct AES_ctx* ctx = (struct AES_ctx* ) td->context;
	if (!ctx) {
		GF_SAFEALLOC(ctx, struct AES_ctx);
		if (ctx == NULL) return GF_OUT_OF_MEM;
		td->context = ctx;
	}

	/* For ctr */
	if (iv) {
		AES_init_ctx_iv(ctx, key, iv);
	} else {
		AES_init_ctx(ctx, key);
	}
	return GF_OK;
}

void gf_crypt_deinit_tinyaes_ctr(GF_Crypt* td)
{
}


GF_Err gf_crypt_encrypt_tinyaes_ctr(GF_Crypt* td, u8 *plaintext, u32 len)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	AES_CTR_xcrypt_buffer(ctx, plaintext, len);
	return GF_OK;
}

GF_Err gf_crypt_decrypt_tinyaes_ctr(GF_Crypt* td, u8 *ciphertext, u32 len)
{
	struct AES_ctx* ctx = (struct AES_ctx *)td->context;
	AES_CTR_xcrypt_buffer(ctx, ciphertext, len);
	return GF_OK;
}


GF_Err gf_crypt_open_open_tinyaes(GF_Crypt* td, GF_CRYPTO_MODE mode)
{
	td->mode = mode;
	switch (td->mode) {
	case GF_CBC:
		td->_init_crypt = gf_crypt_init_tinyaes_cbc;
		td->_deinit_crypt = gf_crypt_deinit_tinyaes_cbc;
		td->_set_key = gf_set_key_tinyaes_cbc;
		td->_crypt = gf_crypt_encrypt_tinyaes_cbc;
		td->_decrypt = gf_crypt_decrypt_tinyaes_cbc;
		td->_get_state = gf_crypt_get_IV_tinyaes_cbc;
		td->_set_state = gf_crypt_set_IV_tinyaes_cbc;
		td->_crypt_enqueue = gf_crypt_encrypt_enqueue_ipsec_mb_cbcs;
		td->_get_completed = gf_crypt_get_completed_ipsec_mb_cbcs;
		td->_flush = gf_crypt_flush_ipsec_mb_cbcs;
		break;
	case GF_CTR:
		td->_init_crypt = gf_crypt_init_tinyaes_ctr;
		td->_deinit_crypt = gf_crypt_deinit_tinyaes_ctr;
		td->_set_key = gf_set_key_tinyaes_ctr;
		td->_crypt = gf_crypt_encrypt_tinyaes_ctr;
		td->_decrypt = gf_crypt_decrypt_tinyaes_ctr;
		td->_get_state = gf_crypt_get_IV_tinyaes_ctr;
		td->_set_state = gf_crypt_set_IV_tinyaes_ctr;
		break;
	default:
		return GF_BAD_PARAM;
		break;

	}
	td->algo = GF_AES_128;
	return GF_OK;
}

#endif

