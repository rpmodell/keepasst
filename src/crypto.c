//utility functions for KDF, Symmetric encryption: chacha20, aes256

#include "crypto.h"

#include <stdio.h>
#include <string.h>
#ifdef __FreeBSD__
#include <strings.h>
#endif

#include <sys/types.h>
#include <sys/param.h>

#include <argon2.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#ifndef LIBRESSL_VERSION_NUMBER
#define USE_SECURE_MALLOC 1
#endif

#define RAND_BUF_LEN 16
#define CHACHA20_IV_LEN 12

static const char B64_ENCODE_LUT[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char B64_DECODE_LUT[256] = {
    ['A']= 0,['B']= 1,['C']= 2,['D']= 3,['E']= 4,['F']= 5,['G']= 6,['H']= 7,
    ['I']= 8,['J']= 9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
    ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
    ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
    ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
    ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
    ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
    ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63,
    ['=']=-2,
};

char *str_clone(const char *str)
{
    if (!str)
        return NULL;
	
    long str_sz = strlen(str);
    char *clone = (char*) malloc((str_sz + 1) * sizeof(char));
    if (clone)
        strcpy(clone, str);

    return clone;
}

void *crypto_secure_malloc(size_t sz)
{
#ifdef USE_SECURE_MALLOC
	if (!CRYPTO_secure_malloc_initialized()) {
		if (!CRYPTO_secure_malloc_init(65536, 32))
			return NULL;
	}

	return OPENSSL_secure_malloc(sz);
#else
    return malloc(sz);
#endif
}

void crypto_secure_free(void *ptr, size_t psz)
{
#ifdef USE_SECURE_MALLOC
	if (CRYPTO_secure_malloc_initialized()) {
		OPENSSL_secure_clear_free(ptr, psz);
	}
#elif defined(__OpenBSD__)
    freezero(ptr, psz);
#else
    explicit_bzero(ptr, psz);
    free(ptr);
#endif
}

int crypto_fill_rand_buf(uint8_t *buf, size_t len)
{
	FILE *fp = fopen("/dev/random", "rb");
	if (!fp)
		return -1;

	if (fread(buf, 1, len, fp) != len)
		return -1;

	fclose(fp);
	return 0;
}

ssize_t b64_encode(char *dest, const size_t destlen, const uint8_t *src, const size_t srclen)
{
	size_t i = 0, doffs = 0;
	char a, b, c;

	if (destlen < B64_ENCODED_LEN(srclen)) {
		return -1;
	}

	memset(dest, 0, destlen);
	for (i = 0; i < srclen; i += 3) {
		if (srclen - i > 0) {
			a = src[i];
			dest[doffs++] = B64_ENCODE_LUT[(a & 0xfc) >> 2];
		}
		
		if (srclen - i > 1) {
			b = src[i + 1];
			dest[doffs++] = B64_ENCODE_LUT[((a & 0x3) << 4) | ((b & 0xf0) >> 4)];
		} else {
			dest[doffs++] = B64_ENCODE_LUT[((a & 0x3) << 4)];
			dest[doffs++] = '=';
			dest[doffs++] = '=';
			break;
		}

		if (srclen - i > 2) {
			c = src[i + 2];
			dest[doffs++] = B64_ENCODE_LUT[((c & 0xc0) >> 6) | ((b & 0xf) << 2)];
			dest[doffs++] = B64_ENCODE_LUT[c & 0x3f];
		} else {
			dest[doffs++] = B64_ENCODE_LUT[((b & 0xf) << 2)];
			dest[doffs++] = '=';
			break;
		}
	}
	
	return doffs;
}

ssize_t b64_decode(uint8_t *dest, const size_t destlen, const char *src, const size_t srclen)
{
	ssize_t doffs = 0;
	ssize_t i;
	ssize_t more;
	char a, b, c, d;

	memset(dest, 0, destlen);
	for(i = 0; i < srclen; i += 4) {
		a = B64_DECODE_LUT[src[i + 0]];
		b = B64_DECODE_LUT[src[i + 1]];
		c = B64_DECODE_LUT[src[i + 2]];
		d = B64_DECODE_LUT[src[i + 3]];
		if (a != -2 && b != -2) {
			dest[doffs++] = (a << 2) | (b >> 4);
		}
		if (b != -2 && c != -2) {
			dest[doffs++] = ((b & 0xf) << 4) | (c >> 2);
		}
		if (c != -2 && d != -2) {
			dest[doffs++] = ((c & 0x3) << 6) | d;
		}
	}

	return doffs;
}

/*
 * For KeePass KDF the key to transform is the double SHA-256 hash of the key (the only supported key is the passphrase as of now)
 */

int kdf_derive_argon2d(uint8_t *out, uint8_t *salt, size_t salt_len, const char *password, uint32_t version, uint64_t m_cost, uint64_t t_cost, uint32_t parallelism)
{
	uint8_t buf[SHA256_DIGEST_LENGTH], key[SHA256_DIGEST_LENGTH];
	SHA256((const uint8_t*) password, strlen(password), buf);
	SHA256(buf, sizeof(buf), key);

	return argon2d_hash_raw(t_cost, (m_cost / 1024), parallelism, key, sizeof(key),
						 	salt, salt_len, out, KDF_DERIVE_LEN) != ARGON2_OK;
}

int kdf_derive_argon2id(uint8_t *out, uint8_t *salt, size_t salt_len, const char *password, uint32_t version, uint64_t m_cost, uint64_t t_cost, uint32_t parallelism)
{
	uint8_t buf[SHA256_DIGEST_LENGTH], key[SHA256_DIGEST_LENGTH];
	SHA256((const uint8_t*) password, strlen(password), buf);
	SHA256(buf, sizeof(buf), key);

	return argon2id_hash_raw(t_cost, (m_cost / 1024), parallelism, key, sizeof(key), 
							 salt, salt_len, out, KDF_DERIVE_LEN) != ARGON2_OK;
}

/*
 * AES256 KDF is a custom KeePass Key Derivation Function and is computed as follows:
 * - like the argon2 keepass requires the password R to be the double SHA-256 of the passphrase
 * - then R is encrypted rounds-times using aes ecb
 * - then the ciphertext is hashed again using SHA-256 to produce the final key
 *
 * for reference keepassxc: https://github.com/keepassxreboot/keepassxc/blob/develop/src/crypto/kdf/AesKdf.cpp
 */
int kdf_derive_kdfaes(uint8_t *out, uint8_t *salt, size_t salt_len, const char *password, uint64_t rounds)
{
	int retval = 1;
	EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, key_len = SHA256_DIGEST_LENGTH;
	
	uint8_t buf[SHA256_DIGEST_LENGTH+16], key[SHA256_DIGEST_LENGTH+16];
	SHA256((const uint8_t*) password, strlen(password), buf);
	SHA256(buf, SHA256_DIGEST_LENGTH, key);

	memset(buf, 0, sizeof(buf));

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		goto fail;

	while (rounds--) {
		if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, salt, NULL) != 1)
			goto fail;

		if (EVP_EncryptUpdate(ctx, buf, &len, key, key_len) != 1)
			goto fail;

		key_len = len;

		if (EVP_EncryptFinal_ex(ctx, buf + len, &len) != 1) 
			goto fail;
	
		key_len += len;

		// swap buffers
		memcpy(key, buf, key_len);
	}

	SHA256(key, key_len, out);

	retval = 0;
fail:
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

	return retval;
}



int hmac_256(uint8_t *out, uint8_t *key, size_t key_len, uint8_t *data, size_t data_len)
{
	unsigned int md_len = 0;
	HMAC(EVP_sha256(), key, key_len, data, data_len, out, &md_len);

	return md_len != SHA256_DIGEST_LENGTH;
}

ssize_t decrypt_aes256_cbc(uint8_t *out, uint8_t *in, size_t in_len, uint8_t *iv, uint8_t *key)
{
	ssize_t retval = -1;
	EVP_CIPHER_CTX *ctx = NULL;
	int len, outlen;

    	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		goto fail;

	if (EVP_DecryptInit(ctx, EVP_aes_256_cbc(), key, iv) != 1) {
		goto fail;
	}

	if (EVP_DecryptUpdate(ctx, out, &len, in, in_len) != 1) {
		goto fail;
	}

	outlen = len;

	if (EVP_DecryptFinal(ctx, out + len, &len) != 1)  {
		goto fail;
	}

	outlen += len;
	retval = outlen;
fail:
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

	return retval;
}

ssize_t decrypt_chacha20(uint8_t *out, uint8_t *in, size_t in_len, uint8_t *iv, uint8_t *key)
{
	ssize_t retval = -1;
	EVP_CIPHER_CTX *ctx = NULL;
	int len, outlen;

    	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		goto fail;

	if (EVP_DecryptInit(ctx, EVP_chacha20(), key, iv) != 1)
		goto fail;

	if (EVP_DecryptUpdate(ctx, out, &len, in, in_len) != 1)
			goto fail;

	outlen = len;

	if (EVP_DecryptFinal(ctx, out + len, &len) != 1) 
		goto fail;

	outlen += len;
	retval = outlen;
fail:
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

	return retval;
}

ssize_t encrypt_aes256_cbc(uint8_t *out, uint8_t *in, size_t in_len, uint8_t *iv, uint8_t *key)
{
	ssize_t retval = -1;
	EVP_CIPHER_CTX *ctx = NULL;
	int len, outlen;

    	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		goto fail;

	if (EVP_EncryptInit(ctx, EVP_aes_256_cbc(), key, iv) != 1) {
		goto fail;
	}

	if (EVP_EncryptUpdate(ctx, out, &len, in, in_len) != 1) {
		goto fail;
	}

	outlen = len;

	if (EVP_EncryptFinal(ctx, out + len, &len) != 1)  {
		goto fail;
	}

	outlen += len;
	retval = outlen;
fail:
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

	return retval;
}

ssize_t encrypt_chacha20(uint8_t *out, uint8_t *in, size_t in_len, uint8_t *iv, uint8_t *key)
{
	ssize_t retval = -1;
	EVP_CIPHER_CTX *ctx = NULL;
	int len, outlen;

    	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		goto fail;

	if (EVP_EncryptInit(ctx, EVP_chacha20(), key, iv) != 1)
		goto fail;

	if (EVP_EncryptUpdate(ctx, out, &len, in, in_len) != 1)
			goto fail;

	outlen = len;

	if (EVP_EncryptFinal(ctx, out + len, &len) != 1) 
		goto fail;

	outlen += len;
	retval = outlen;
fail:
    	/* Clean up */
    	EVP_CIPHER_CTX_free(ctx);

	return retval;
}

EVP_CIPHER_CTX *rnd_stream_new(int type, uint8_t *key, size_t key_len)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len, outlen;

	uint8_t tkey[SHA512_DIGEST_LENGTH];
	SHA512(key, key_len, tkey);
	memmove(tkey + 36, tkey + 32, CHACHA20_IV_LEN);
	memset(tkey + 32, 0, 4);

    	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}

	if (EVP_EncryptInit(ctx, EVP_chacha20(), tkey, tkey + 32) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		return NULL;
	}
	
	return ctx;
}

int rnd_stream_xor(EVP_CIPHER_CTX *ctx, uint8_t *data, size_t len)
{
	int elen;
	size_t i, chuck, total = 0;
	uint8_t zero_buf[RAND_BUF_LEN], rand_buf[RAND_BUF_LEN];
	for (total = 0; total < len; total += RAND_BUF_LEN) {
		chuck = MIN(len - total, RAND_BUF_LEN);
		memset(zero_buf, 0, sizeof(zero_buf));
		if (EVP_EncryptUpdate(ctx, rand_buf, &elen, zero_buf, chuck) != 1) {
			return -1;
		}

		if (EVP_EncryptFinal(ctx, rand_buf + elen, &elen) != 1) {
			return -1;
		}

		for (i = 0; i < chuck; i++) {
			*(data + total + i) ^= rand_buf[i];
		}
	}
	
	return 0;
}

int rnd_stream_close(EVP_CIPHER_CTX *ctx)
{
	EVP_CIPHER_CTX_free(ctx);
    return 0;
}
