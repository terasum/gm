// ----- KDF FUNCTIONS START -----
//typedef void *(*KDF)(const void *in, size_t inlen, void *out, size_t *outlen);

#pragma once
#include <memory.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
//void EVP_MD_CTX_init(EVP_MD_CTX *ctx)
//{
//    memset(ctx, '\0', sizeof *ctx);
//}
//
//int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx)
//{
//#ifndef OPENSSL_FIPS
//    /*
// *      * Don't assume ctx->md_data was cleaned in EVP_Digest_Final, because
// *           * sometimes only copies of the context are ever finalised.
// *                */
//    if (ctx->digest && ctx->digest->cleanup
//        && !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_CLEANED))
//        ctx->digest->cleanup(ctx);
//    if (ctx->digest && ctx->digest->ctx_size && ctx->md_data
//        && !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_REUSE)) {
//        OPENSSL_cleanse(ctx->md_data, ctx->digest->ctx_size);
//        OPENSSL_free(ctx->md_data);
//    }
//#endif
//    if (ctx->pctx)
//        EVP_PKEY_CTX_free(ctx->pctx);
//#ifndef OPENSSL_NO_ENGINE
//    if (ctx->engine)
//        /*
// *          * The EVP_MD we used belongs to an ENGINE, release the functional
// *                   * reference we held for this reason.
// *                            */
//        ENGINE_finish(ctx->engine);
//#endif
//#ifdef OPENSSL_FIPS
//    FIPS_md_ctx_cleanup(ctx);
//#endif
//    memset(ctx, '\0', sizeof *ctx);
//
//    return 1;
//}

int x9_63_kdf(const EVP_MD *md, const unsigned char *share, size_t sharelen, size_t keylen, unsigned char *outkey)
{
	int ret = 0;

	EVP_MD_CTX ctx;
	unsigned char counter[4] = {0, 0, 0, 1};
	unsigned char dgst[EVP_MAX_MD_SIZE];
	unsigned int dgstlen;
	int rlen = (int)keylen;
	unsigned char * pp;

	pp = outkey;

	if (keylen > (size_t)EVP_MD_size(md)*255)
	{
		fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
		goto end;
	}

	while (rlen > 0)
	{
		EVP_MD_CTX_init(&ctx);

		if (!EVP_DigestInit(&ctx, md))
		{
			fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
			goto end;
		}

		if (!EVP_DigestUpdate(&ctx, share, sharelen))
		{
			fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
			goto end;
		}
		if (!EVP_DigestUpdate(&ctx, counter, 4))
		{
			fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
			goto end;
		}
		if (!EVP_DigestFinal(&ctx, dgst, &dgstlen))
		{
			fprintf(stderr, "%s(%d):", __FILE__, __LINE__);
			goto end;
		}

		EVP_MD_CTX_cleanup(&ctx);

		memcpy(pp, dgst, keylen>=dgstlen ? dgstlen:keylen);

		rlen -= dgstlen;
		pp += dgstlen;
		counter[3]++;
	}

	ret = 1;

end:
	return ret;
}

// ----- KDF FUNCTIONS END -----
