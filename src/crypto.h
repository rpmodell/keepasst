#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <openssl/evp.h>

#define KDF_DERIVE_LEN 32

#define B64_ENCODED_LEN(L) ((((L) + 2) / 3) * 4)
#define B64_DECODED_LEN(L) (((L) + 3) / 4 * 3)

char *str_clone(const char *str);

void *crypto_secure_malloc(size_t sz);
void crypto_secure_free(void *ptr, size_t size);

int crypto_fill_rand_buf(uint8_t *buf, size_t len);

ssize_t b64_encode(char *dest, const size_t destlen, const uint8_t *src, const size_t srclen);
ssize_t b64_decode(uint8_t *dest, const size_t destlen, const char *src, const size_t srclen);


int kdf_derive_argon2d(uint8_t *out, uint8_t *salt, size_t salt_len, const char *password, 
    uint32_t version, uint64_t m_cost, uint64_t t_cost, uint32_t threads);

int kdf_derive_argon2id(uint8_t *out, uint8_t *salt, size_t salt_len, const char *password, 
    uint32_t version, uint64_t m_cost, uint64_t t_cost, uint32_t threads);

int kdf_derive_kdfaes(uint8_t *out, uint8_t *salt, size_t salt_len, const char *password, uint64_t rounds);

int hmac_256(uint8_t *out, uint8_t *key, size_t key_len, uint8_t *data, size_t data_len);

ssize_t decrypt_aes256_cbc(uint8_t *out, uint8_t *in, size_t in_len, uint8_t *iv, uint8_t *key);
ssize_t decrypt_chacha20(uint8_t *out, uint8_t *in, size_t in_len, uint8_t *iv, uint8_t *key);

ssize_t encrypt_aes256_cbc(uint8_t *out, uint8_t *in, size_t in_len, uint8_t *iv, uint8_t *key);
ssize_t encrypt_chacha20(uint8_t *out, uint8_t *in, size_t in_len, uint8_t *iv, uint8_t *key);

EVP_CIPHER_CTX *rnd_stream_new(int type, uint8_t *key, size_t key_len);
int rnd_stream_xor(EVP_CIPHER_CTX *ctx, uint8_t *data, size_t len);
int rnd_stream_close(EVP_CIPHER_CTX *ctx);

#endif
