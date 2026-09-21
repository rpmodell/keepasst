/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of the  nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 */


#ifndef __KDBX_H__
#define __KDBX_H__

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <sys/types.h>

#define KDBX_GENERATOR "keepasst"

#define MASTER_SALT_LEN 32

/* KDBX error codes */
#define ERR_KDBX_IO -1
#define ERR_KDBX_INVALID -2
#define ERR_KDBX_UNSUPPORTED_ENC_ALGORITHM -3
#define ERR_KDBX_UNSUPPORTED_KDF_ALGORITHM -4
#define ERR_KDBX_VERIFY_HASH -5
#define ERR_KDBX_VERIFY_HMAC -6
#define ERR_KDBX_COMPRESSION -7
#define ERR_KDBX_DECRYPT -8
#define ERR_KDBX_ENCRYPT ERR_KDBX_DECRYPT
#define ERR_KDBX_KDF_TRANSFORM -9
#define ERR_KDBX_INVALID_XML -10

enum KDBXEncryption {
	KDBX_AES256 = 1, 	// UUID 31C1F2E6BF714350BE5805216AFC5AFF: AES-256 (NIST FIPS 197, CBC mode, PKCS #7 padding)
	KDBX_SALSA20 = 2, 	// UUID 31C1F2E6BF714350BE5805216AFC5AFF: AES-256 (NIST FIPS 197, CBC mode, PKCS #7 padding)
	KDBX_CHACHA20 = 3	// UUID D6038A2B8B6F4CB5A524339A31DBB59A: ChaCha20 (RFC 8439).
};

enum KDBXKDFType {
	KDBX_KDF_AES,		// UUID C9D9F39A628A4460BF740D08C18A4FEA: AES-KDF
	KDBX_KDF_ARGON_2D,	// UUID EF636DDF8C29444B91F7A9A403E30A0C: Argon2d
	KDBX_KDF_ARGON_2ID	// UUID 9E298B1956DB4773B23DFC3EC6F0A1E6: Argon2id
};


/*
Name	ID	Type	Description
End of header	0	–	Indicates the end of the header. Must be present exactly once, as the last header field. The value should be empty.
Inner encryption algorithm	1	Int32	2 = Salsa20, 3 = ChaCha20 (default, recommended). See 'Inner Encryption'.
Inner encryption key (rload)	2	Byte[]	See 'Inner Encryption'.
Binary content	3	Byte[]	The value is f ‖ C, where f is a flags byte and C is the content of a binary (attachment). The flag 0x01 indicates that the binary content should be protected in the process memory. A binary content is referenced in the XML document by its index in the inner header (the first binary content has index 0, the second one has index 1, etc.).*/

// The timeinfo is stored in unix time however the kdbx time is since jan 2001
typedef struct {
	time_t last_mod;
	time_t creation;
	time_t expiration;
} KDBXTimeInfo;

typedef struct {
	KDBXTimeInfo time_info;
	size_t values_capacity;
	size_t values_count;
	struct {
		char *key;
		char *value;
		int protect;
	} *values;
} KDBXEntry;

typedef struct {
	KDBXTimeInfo time_info;
	char *name;
	size_t entries_capacity;
	size_t entries_count;
	KDBXEntry *entries;
} KDBXGroup;

typedef struct {
	uint32_t version_major;
	uint32_t version_minor;
	int compressed;
	enum KDBXEncryption encr;
	uint8_t master_salt[MASTER_SALT_LEN];
	uint8_t iv[16]; // for ChaCha20 is 12 bytes for aes is 16
	enum KDBXKDFType kdf_type;
	size_t kdf_salt_len;
	uint8_t *kdf_salt;
	union {
		struct {
			uint64_t rounds;
		} kdf_aes;
		struct {
			uint32_t version;
			uint64_t iterations;
			uint64_t memory;
			uint32_t parallelism;
		} kdf_argon2;
	} kdf;
	
	// In version 4 the data is divided in single encrypted blocks
	enum KDBXEncryption inner_encr;
	size_t inner_key_len;
	uint8_t *inner_key;

	// Inner contents ref is unused for now but readed and writed
	size_t inner_contents_len;
	struct {
		uint64_t blockid;
		size_t content_len;
		uint8_t *content;
	} *inner_contents;

	size_t groups_count;
	KDBXGroup *groups;
} KDBX;

/* KDBX */
const char *kdbx_strerror(int err);
void kdbx_init(KDBX *db);
void kdbx_free(KDBX *db);

int kdbx_set_kdf_type(KDBX *db, enum KDBXKDFType type);

int kdbx_generate_salts(KDBX *db);
int kdbx_read(KDBX *db, const char *fpath, const char *password);
int kdbx_write(KDBX *db, const char *fpath, const char *password);

/* Entries and Groups */
KDBXGroup *kdbx_add_group(KDBX *db, const char *group_name);
KDBXGroup *kdbx_get_group(KDBX *db, size_t i);
ssize_t kdbx_find_group(KDBX *db, const char *group_name);
int kdbx_remove_group(KDBX *db, const size_t index);
int kdbx_group_set_name(KDBX *db, const size_t index, const char *name);

int kdbx_entry_put_value(KDBXEntry *e, const char *key, const char *val);
char *kdbx_entry_get_value(KDBXEntry *e, const char *key);
int kdbx_entry_set_value(KDBXEntry *e, size_t vidx, const char *val);
int kdbx_entry_set_protected(KDBXEntry *e, size_t vidx, int protect);
KDBXEntry *kdbx_group_add_entry(KDBXGroup *group, int expires);
int kdbx_group_remove_entry(KDBXGroup *group, size_t index);

#endif

