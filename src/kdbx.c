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


#include "kdbx.h"

#include "crypto.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <endian.h>
#include <sys/types.h>
#include <sys/param.h>

#include <openssl/sha.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xinclude.h>
#include <libxml/xmlIO.h>
#include <zlib.h>

// #define DEBUG_NOVERIFY_HMAC 1

#define ZCHUCK 16384
#define MAX_HMAC_BLOCK_LEN 1048576
#define KEEPASS_EPOCH (62135596800)

#define UUID_LEN 16
#define AES256_IV_LEN 16
#define CHACHA20_IV_LEN 12

#define SIGNATURE_1 0x9AA2D903
#define SIGNATURE_2 0xB54BFB67
#define HEADER_END 0x0A0D0A0D

#define VARIANT_DICT_VERSION 0x0100

#define VARIANT_UINT32 0x04 // UInt32.
#define VARIANT_UINT64 0x05 // UInt64.
#define VARIANT_BOOL   0x08 // Boolean.
#define VARIANT_INT32  0x0C // Int32.
#define VARIANT_INT64  0x0D // Int64.
#define VARIANT_STRING 0x18 // String.
#define VARIANT_BYTES  0x42 // Byte[].

#define IV_LEN(ET) (ET == KDBX_AES256 ? AES256_IV_LEN : CHACHA20_IV_LEN)
#define INNER_KEY_LEN(ET) (ET == KDBX_SALSA20 ? 32 :64)

#define VARIANT_SIZE(NAME, L) (1 + 2 * sizeof(int32_t) + strlen(NAME) + L)
#define VARIANT_SET_UINT32(V, NAME, VALUE) do {\
	(V).type = VARIANT_UINT32;\
	strncpy((V).name, NAME, sizeof((V).name) - 1);\
	(V).value.uint32 = VALUE;\
} while (0);
#define VARIANT_SET_UINT64(V, NAME, VALUE) do {\
	(V).type = VARIANT_UINT64;\
	strncpy((V).name, NAME, sizeof((V).name) - 1);\
	(V).value.uint64 = VALUE;\
} while (0);
#define VARIANT_SET_BOOL(V, NAME, VALUE) do {\
	(V).type = VARIANT_BOOL;\
	strncpy((V).name, NAME, sizeof((V).name) - 1);\
	(V).value.boolean = VALUE;\
} while (0);
#define VARIANT_SET_INT32(V, NAME, VALUE) do {\
	(V).type = VARIANT_INT32;\
	strncpy((V).name, NAME, sizeof((V).name) - 1);\
	(V).value.int32 = VALUE;\
} while (0);
#define VARIANT_SET_INT64(V, NAME, VALUE) do {\
	(V).type = VARIANT_INT64;\
	strncpy((V).name, NAME, sizeof((V).name) - 1);\
	(V).value.int64 = VALUE;\
} while (0);
#define VARIANT_SET_STRING(V, NAME, VALUE) do {\
	(V).type = VARIANT_STRING;\
	strncpy((V).name, NAME, sizeof((V).name) - 1);\
	(V).value.string = VALUE;\
} while (0);
#define VARIANT_SET_BYTES(V, NAME, VALUE, LEN) do {\
	(V).type = VARIANT_BYTES;\
	strncpy((V).name, NAME, sizeof((V).name) - 1);\
	(V).value.bytes.data = (uint8_t*) (VALUE);\
	(V).value.bytes.len = LEN;\
} while (0);
#define VARIANT_SET_END(V) do {\
	(V).type = 0;\
	memset((V).name, 0, sizeof((V).name));\
} while (0);

const uint8_t AES256_UUID[16] = {
	0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50, 0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF
};

const uint8_t CHACHA20_UUID[16] = {
	0xD6, 0x03, 0x8A, 0x2B, 0x8B, 0x6F, 0x4C, 0xB5, 0xA5, 0x24, 0x33, 0x9A, 0x31, 0xDB, 0xB5, 0x9A
};

const uint8_t KDF_AES_UUID[16] = {
	0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA
};

const uint8_t KDF_ARGON_2D_UUID[16] = {
	0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C
};

const uint8_t KDF_ARGON_2ID_UUID[16] = {
	0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFC, 0x3E, 0xC6, 0xF0, 0xA1, 0xE6
};

static void hexprint(uint8_t *arr, size_t size, const char *title)
{
	size_t i;
	printf("================== %s [%zu bytes] =====================\n", title, size);
	for (i = 0; i < size; i += 2) {
		printf("%02x", arr[i]);
		if (i + 1 < size)
			printf("%02x ", arr[i+1]);
		if ((i+1) % 8 == 0)
			printf("\n");
	}
	printf("\n");
}

/* ================================ KDBX ===================================================== */

const char *kdbx_strerror(int err)
{
	switch (err) {
	case ERR_KDBX_IO:
		return "KDBX IO error";
	case ERR_KDBX_INVALID:
		return "KDBX invalid db";
	case ERR_KDBX_UNSUPPORTED_ENC_ALGORITHM:
		return "KDBX unsupported encryption algorithm";
	case ERR_KDBX_UNSUPPORTED_KDF_ALGORITHM:
		return "KDBX unsupported key derivation function algorithm";
	case ERR_KDBX_VERIFY_HASH:
		return "KDBX error verify header hash";
	case ERR_KDBX_VERIFY_HMAC:
		return "KDBX error verify block HMAC";
	case ERR_KDBX_COMPRESSION:
		return "KDBX error compression";
	case ERR_KDBX_DECRYPT:
		return "KDBX error decrypt/encrypt database";
	case ERR_KDBX_KDF_TRANSFORM:
		return "KDBX error key derivation";
	case ERR_KDBX_INVALID_XML:
		return "KDBX invalid database XML content";
	default:
		return "KDBX error unknown";
	}
}

void kdbx_init(KDBX *db)
{
	db->version_major = 4;
	db->version_minor = 0;
	db->compressed = 0;
	db->encr = KDBX_AES256;

	kdbx_set_kdf_type(db, KDBX_KDF_ARGON_2D);
	
	db->inner_encr = KDBX_CHACHA20;
	db->inner_key_len = INNER_KEY_LEN(db->inner_encr);
	db->inner_key = (uint8_t*) malloc(db->inner_key_len * sizeof(uint8_t));

	db->inner_contents_len = 0;
	db->inner_contents = NULL;


	db->groups_count = 0;
	db->groups = NULL;
}

static void entry_free(KDBXEntry *e)
{
	while (e->values_count--) {
		free(e->values[e->values_count].key);
		if (e->values[e->values_count].value)
			crypto_secure_free(e->values[e->values_count].value);
	}
	free(e->values);
	e->values = NULL;
}

static void group_free(KDBXGroup *group)
{
	while (group->entries_count--)
		entry_free(group->entries + group->entries_count);

	free(group->entries);
	group->entries = NULL;
}

void kdbx_free(KDBX *db)
{
	if (!db)
		return;

	free(db->kdf_salt);
	db->kdf_salt = NULL;

	while (db->groups_count--)
		group_free(db->groups + db->groups_count);

	free(db->groups);
	db->groups = NULL;

	while (db->inner_contents_len--)
		free(db->inner_contents[db->inner_contents_len].content);

	free(db->inner_contents);
	db->inner_contents = NULL;
}

int kdbx_set_kdf_type(KDBX *db, enum KDBXKDFType type)
{
	if (!db)
		return -1;

	switch (type) {
	case KDBX_KDF_ARGON_2D:
	case KDBX_KDF_ARGON_2ID:
		//follow reccomendations for argon2 by ietf
		db->kdf_type = type;
		db->kdf_salt_len = 0;
		db->kdf_salt = NULL;
		db->kdf.kdf_argon2.version = 0x13;
		db->kdf.kdf_argon2.iterations = 10;
		db->kdf.kdf_argon2.memory = 64 * 1024 * 1024;
		db->kdf.kdf_argon2.parallelism = 2;
		break;
	case KDBX_KDF_AES:
		db->kdf_type = type;
		db->kdf_salt_len = 0;
		db->kdf_salt = NULL;
		db->kdf.kdf_aes.rounds = 19867550;
		break;
	default:
		return -1;
	}

	return 0;
}

int kdbx_generate_salts(KDBX *db)
{
	int ret = -1;
	size_t i, salt_len = 0;
	FILE *fp = fopen("/dev/random", "rb");
	if (!fp) {
		goto gen_salts_fail;
	}

	if (fread(db->master_salt, 1, sizeof(db->master_salt), fp) != sizeof(db->master_salt)) {
		goto gen_salts_fail;
	}
	if (fread(db->iv, 1, IV_LEN(db->encr), fp) != IV_LEN(db->encr)) {
		goto gen_salts_fail;
	}
	
	salt_len = 32;
	if (!db->kdf_salt || db->kdf_salt_len < salt_len) {
		db->kdf_salt_len = salt_len;
		db->kdf_salt = (uint8_t*) realloc(db->kdf_salt, salt_len * sizeof(uint8_t));
	}
	if (fread(db->kdf_salt, 1, db->kdf_salt_len, fp) != db->kdf_salt_len) {
		goto gen_salts_fail;
	}

	salt_len = INNER_KEY_LEN(db->inner_encr);
	if (!db->inner_key || db->inner_key_len < salt_len) {
		db->inner_key_len = salt_len;
		db->inner_key = (uint8_t*) realloc(db->inner_key, salt_len * sizeof(uint8_t));
	}
	if (fread(db->inner_key, 1, db->inner_key_len, fp) != db->inner_key_len) {
		goto gen_salts_fail;
	}


	ret = 0;
gen_salts_fail:
	fclose(fp);
}

/* Entries */


static inline int entry_put_value(KDBXEntry *e, const char *key, const char *val, int protect)
{
	if (e->values_count + 1 >= e->values_capacity) {
		e->values_capacity = MAX(e->values_capacity * 2, 10);
		e->values = realloc(e->values, e->values_capacity * sizeof(*e->values));
	}

	e->values[e->values_count].key = str_clone(key);
	e->values[e->values_count].value = NULL;
	if (val) {
		size_t vlen = strlen(val) + 1;
		e->values[e->values_count].value = crypto_secure_malloc(vlen);
		memcpy(e->values[e->values_count].value, val, vlen);
	}
	e->values[e->values_count].protect = protect;
	e->values_count++;
	return 0;
}

int kdbx_entry_put_value(KDBXEntry *e, const char *key, const char *val)
{
	if (entry_put_value(e, key, val, 0))
		return -1;

	e->time_info.last_mod = time(NULL);
}

char *kdbx_entry_get_value(KDBXEntry *e, const char *key)
{
	if (!e)
		return NULL;

	size_t i;
	for (i = 0; i < e->values_count; i++) {
		if (!strcmp(e->values[i].key, key))
			return e->values[i].value;
	}
	
	return NULL;
}

int kdbx_entry_set_value(KDBXEntry *e, size_t vidx, const char *val)
{
	if (vidx >= e->values_count)
		return -1;

	if (val) {
		size_t vlen = strlen(val) + 1;
		e->values[vidx].value = crypto_secure_realloc(e->values[vidx].value, vlen);
		memcpy(e->values[vidx].value, val, vlen);
	}

	e->time_info.last_mod = time(NULL);
	return 0;
}

int kdbx_entry_set_protected(KDBXEntry *e, size_t vidx, int protect)
{
	if (vidx >= e->values_count)
		return -1;

	//FIXME when memory protection is in place this will change the
	//value to encrypted in memory
	e->values[vidx].protect = protect;
	e->time_info.last_mod = time(NULL);
	return 0;
}

/* Groups */
KDBXGroup *kdbx_add_group(KDBX *db, const char *group_name)
{
	db->groups = (KDBXGroup*) realloc(db->groups, (db->groups_count + 1) * sizeof(KDBXGroup));
	if (!db->groups) {
		return NULL;
	}

	KDBXGroup *g = &db->groups[db->groups_count++];
	g->name = str_clone(group_name);
	g->entries = NULL;
	g->entries_count = 0;
	g->entries_capacity = 0;

	g->time_info.creation = time(NULL);
	g->time_info.last_mod = time(NULL);
	g->time_info.expiration = 0;
	return g;
}


KDBXGroup *kdbx_get_group(KDBX *db, size_t i)
{
	if (i >= db->groups_count) {
		return NULL;
	}

	return &db->groups[i];
}

ssize_t kdbx_find_group(KDBX *db, const char *group_name)
{
	size_t i;
	for (i = 0; i < db->groups_count; i++) {
		if (!strcmp(db->groups[i].name, group_name))
			return i;
	}

	return -1;
}

int kdbx_remove_group(KDBX *db, size_t index)
{
	if (index >= db->groups_count)
		return -1;

	size_t i;
	db->groups_count--;
	group_free(db->groups + index);
	for (i = index; i < db->groups_count; i++) {
		db->groups[i] = db->groups[i+1];
	}

	// Since the number of groups is generally 1/2 for now lets realloc the mem every time a group is added removed
	db->groups = (KDBXGroup*) realloc(db->groups, db->groups_count * sizeof(KDBXGroup));
	if (!db->groups) {
		return -1;
	}

	return 0;
}

int kdbx_group_set_name(KDBX *db, const size_t index, const char *name)
{
	if (index >= db->groups_count)
		return -1;

	KDBXGroup *g = db->groups + index;
	if (g->name)
		free(g->name);

	g->name = str_clone(name);
	return 0;
}

KDBXEntry *kdbx_group_add_entry(KDBXGroup *group, int expires)
{
	if (!group) {
		return NULL;
	}

	if (group->entries_count + 1 >= group->entries_capacity) {
		group->entries_capacity = MAX(group->entries_capacity * 2, 5);
		group->entries = realloc(group->entries, group->entries_capacity * sizeof(KDBXEntry));
		if (!group->entries) 
			return NULL;
	}

	KDBXEntry *e = &group->entries[group->entries_count++];
	e->values_count = 0;
	e->values_capacity = 0;
	e->values = NULL;
	e->time_info.creation = time(NULL);
	e->time_info.last_mod	= time(NULL);
	e->time_info.expiration = 0;
	group->time_info.last_mod = time(NULL);
	return e;
}

int kdbx_group_remove_entry(KDBXGroup *group, size_t index)
{
	if (index >= group->entries_count) {
		return -1;
	}

	size_t i;
	group->entries_count--;
	entry_free(group->entries + index);
	for (i = index; i < group->entries_count; i++) {
		group->entries[i] = group->entries[i+1];
	}

	// Since the number of groups is generally 1/2 for now lets realloc the mem every time a group is added removed
	group->entries = (KDBXEntry*) realloc(group->entries, group->entries_count * sizeof(KDBXEntry));
	if (!group->entries)
		return -1;

	return 0;
}
/* ================================ KDBXBlock ================================================= */
static inline int add_inner_content(KDBX *db, uint64_t blockid, uint8_t *content, size_t content_len)
{
	db->inner_contents = realloc(db->inner_contents, db->inner_contents_len + 1);
	if (db->inner_contents)
		return -1;

	db->inner_contents[db->inner_contents_len].blockid = blockid;
	db->inner_contents[db->inner_contents_len].content_len = content_len;
	db->inner_contents[db->inner_contents_len].content = content;
	db->inner_contents_len++;

	return 0;
}

/*=================================== HELPER KEY GENERATION FUNCTIONS ============================ */

static void crypto_hmac_key(uint8_t *out, uint8_t *master_salt, uint8_t *tx_key, size_t tx_key_len, uint64_t i) 
{
	uint8_t buffer[MASTER_SALT_LEN + KDF_DERIVE_LEN + 1];
	uint8_t buffer2[sizeof(i) + SHA512_DIGEST_LENGTH];
	//SHA-512(0xFF FF FF FF FF FF FF FF or i ‖ SHA-512(S ‖ T ‖ 0x01)).

	memcpy(buffer, master_salt, MASTER_SALT_LEN);
	memcpy(buffer + MASTER_SALT_LEN, tx_key, tx_key_len);
	buffer[MASTER_SALT_LEN + tx_key_len] = 0x01;
	SHA512(buffer, MASTER_SALT_LEN + tx_key_len + 1, buffer2 + sizeof(i));
	memcpy(buffer2, &i, sizeof(i));
	SHA512(buffer2, sizeof(buffer2), out);
}

/*
If the encryption algorithm needs a 256-bit key (such as AES-256 and ChaCha20), the key is: 
* 	SHA-256(S ‖ T). 
*/
static void crypto_final_key(uint8_t *out, uint8_t *master_salt, uint8_t *tx_key, size_t tx_key_len)
{
	uint8_t buffer[MASTER_SALT_LEN + KDF_DERIVE_LEN];
	memcpy(buffer, master_salt, MASTER_SALT_LEN);
	memcpy(buffer + MASTER_SALT_LEN, tx_key, tx_key_len);
	SHA256(buffer, sizeof(buffer), out);
}

static inline int transform_key(KDBX *db, const char *password, uint8_t *out)
{
	switch (db->kdf_type) {
	case KDBX_KDF_AES:
		return kdf_derive_kdfaes(out, db->kdf_salt, db->kdf_salt_len, password, db->kdf.kdf_aes.rounds);
	case KDBX_KDF_ARGON_2D:
		return kdf_derive_argon2d(out, db->kdf_salt, db->kdf_salt_len, password, db->kdf.kdf_argon2.version, 
					db->kdf.kdf_argon2.memory, db->kdf.kdf_argon2.iterations, db->kdf.kdf_argon2.parallelism); 
	case KDBX_KDF_ARGON_2ID:
		return kdf_derive_argon2id(out, db->kdf_salt, db->kdf_salt_len, password, db->kdf.kdf_argon2.version, 
					db->kdf.kdf_argon2.memory, db->kdf.kdf_argon2.iterations, db->kdf.kdf_argon2.parallelism);
	}

	return -1;
}

/*================================= READ / WRITE KDBX =========================================*/

/*A variant dictionary is a name-value dictionary, where the name is a string and the type of the value depends on the item. It is stored as follows:

Format version, as UInt16.
The high byte is the major version. It is critical, i.e. an application must refuse to load the file if the major version is unsupported.
The low byte is the minor version. It can be ignored, but when encountering an unsupported value type, a confirmation/warning should be displayed or loading should fail.
The current version is 1.0, i.e. 0x0100.
Zero or more items (see below).
Null terminator byte.
An item looks as follows:

Name	Type	Description
Value type t	Byte	Supported value types are:
0x04: UInt32.
0x05: UInt64.
0x08: Boolean.
0x0C: Int32.
0x0D: Int64.
0x18: String.
0x42: Byte[].
Name size r	Int32	Size of U in bytes.
Name U	String (r bytes)	Name of the item.
Value size s	Int32	Size of V in bytes.
Value V	t (s bytes)	Value of the item.
The order of the items is arbitrary.*/
struct variant {
	int type;
	char name[65];
	union {
		uint64_t uint64;
		int64_t int64;
		uint32_t uint32;
		int32_t int32;
		int boolean;
		char *string;
		struct {
			size_t len;
			uint8_t *data;
		} bytes;
	} value;
};

static int read_uint16(uint16_t *n, FILE *fp)
{
	if (fread(n, sizeof(*n), 1, fp) != 1) {
		return -1;
	}

	*n = le16toh(*n);
	return 0;
}

static int write_uint16(uint16_t n, FILE *fp)
{
	n = htole16(n);
	if (fwrite(&n, sizeof(n), 1, fp) != 1) {
		return -1;
	}

	return 0;
}

static int read_uint32(uint32_t *n, FILE *fp)
{
	if (fread(n, sizeof(*n), 1, fp) != 1) {
		return -1;
	}

	*n = le32toh(*n);
	return 0;
}

static int write_uint32(uint32_t n, FILE *fp)
{
	n = htole32(n);
	if (fwrite(&n, sizeof(n), 1, fp) != 1) {
		return -1;
	}

	return 0;
}

static int read_int32(int32_t *n, FILE *fp)
{
	uint32_t v = 0;
	if (fread(&v, sizeof(v), 1, fp) != 1) {
		return -1;
	}

	*n = (int32_t) le32toh(v);
	return 0;
}

static int write_int32(int32_t v, FILE *fp)
{
	uint32_t n = htole32(v);
	if (fwrite(&n, sizeof(n), 1, fp) != 1) {
		return -1;
	}

	return 0;
}

static int read_uint64(uint64_t *n, FILE *fp)
{
	if (fread(n, sizeof(*n), 1, fp) != 1) {
		return -1;
	}

	*n = le64toh(*n);
	return 0;
}

static int write_uint64(uint64_t n, FILE *fp)
{
	n = htole64(n);
	if (fwrite(&n, sizeof(n), 1, fp) != 1) {
		return -1;
	}

	return 0;
}

static int read_int64(int64_t *n, FILE *fp)
{
	uint64_t v = 0;
	if (fread(&v, sizeof(v), 1, fp) != 1) {
		return -1;
	}

	*n = (int64_t) le64toh(v);
	return 0;
}

static int write_int64(int64_t v, FILE *fp)
{
	uint64_t n = htole64(v);
	if (fwrite(&n, sizeof(n), 1, fp) != 1) {
		return -1;
	}

	return 0;
}

static int read_bytes(uint8_t *out, size_t size, FILE *fp)
{
	int ret = 0;
	size_t nread;
	while (size) {
		nread = size > 4096 ? 4096 : size;
		if (fread(out, 1, nread, fp) != nread) {
			ret = -1;
			break;
		}

		out += nread;
		size -= nread;
	}

	return ret;
}

static int write_bytes(uint8_t *in, size_t size, FILE *fp)
{
	int ret = 0;
	size_t nwrite;
	while (size) {
		nwrite = size > 4096 ? 4096 : size;
		if (fwrite(in, 1, nwrite, fp) != nwrite) {
			ret = -1;
			break;
		}

		in += nwrite;
		size -= nwrite;
	}

	return ret;
}

static int read_variant(struct variant *var, FILE *fp)
{
	memset(var, 0, sizeof(struct variant));
	var->type = fgetc(fp);
	if (var->type == 0) {
		return 1;
	}
	if (var->type == EOF) {
		return -1;
	}

	int32_t len = 0;
	if (read_int32(&len, fp)) {
		return -1;
	}

	if (fread(var->name, sizeof(char), len, fp) != len) {
		return -1;
	}

	if (read_int32(&len, fp)) {
		return -1;
	}

	switch (var->type) {
	case VARIANT_UINT32:
		if (read_uint32(&var->value.uint32, fp) || len != sizeof(var->value.uint32))
			return -1;

		break;
	case VARIANT_UINT64:
		if (read_uint64(&var->value.uint64, fp) || len != sizeof(var->value.uint64))
			return -1;

		break;
	case VARIANT_INT32:
		if (read_int32(&var->value.int32, fp) || len != sizeof(var->value.int32))
			return -1;

		break;
	case VARIANT_INT64:
		if (read_int64(&var->value.int64, fp) || len != sizeof(var->value.int64))
			return -1;

		break;
	case VARIANT_BOOL:
		if (len != 1) {
			return -1;
		}

		var->value.boolean = fgetc(fp);
		break;
	case VARIANT_STRING:
		var->value.string = (char*) malloc((len+1) * sizeof(char));
		if (fread(var->value.string, sizeof(char), len, fp) != len)
			return -1;

		var->value.string[len] = '\0';
		break;
	case VARIANT_BYTES:
		var->value.bytes.data = (uint8_t*) malloc(len * sizeof(uint8_t));
		if (fread(var->value.bytes.data, sizeof(uint8_t), len, fp) != len) 
			return -1;

		var->value.bytes.len = len;
		break;
	default:
		return -2; // Invalid type
	}

	return 0;
}

static int write_variant(struct variant *var, FILE *fp)
{
	int32_t len = 0;
	if (fputc(var->type, fp) == EOF) {
		return -1;
	}
	if (var->type == 0) {
		return 0;
	}

	len = strlen(var->name);
	if (write_int32(len, fp)) {
		return -1;
	}
	if (write_bytes((uint8_t*) var->name, len, fp)) {
		return -1;
	}

	switch (var->type) {
	case VARIANT_UINT32:
		len = sizeof(uint32_t);
		break;
	case VARIANT_UINT64:
		len = sizeof(uint64_t);
		break;
	case VARIANT_INT32:
		len = sizeof(int32_t);
		break;
	case VARIANT_INT64:
		len = sizeof(int64_t);
		break;
	case VARIANT_BOOL:
		len = 1;
		break;
	case VARIANT_STRING:
		len = strlen(var->value.string);
		break;
	case VARIANT_BYTES:
		len = var->value.bytes.len;
		break;
	default:
		return -2; // Invalid type
	}

	if (write_int32(len, fp)) {
		return -1;
	}

	switch (var->type) {
	case VARIANT_UINT32:
		if (write_uint32(var->value.uint32, fp))
			return -1;

		break;
	case VARIANT_UINT64:
		if (write_uint64(var->value.uint64, fp))
			return -1;

		break;
	case VARIANT_INT32:
		if (write_int32(var->value.int32, fp))
			return -1;

		break;
	case VARIANT_INT64:
		if (write_int64(var->value.int64, fp))
			return -1;

		break;
	case VARIANT_BOOL:
		if (fputc(var->value.boolean, fp) == EOF)
			return -1;

		break;
	case VARIANT_STRING:
		if (write_bytes((uint8_t*) var->value.string, len, fp))
			return -1;

		break;
	case VARIANT_BYTES:
		if (write_bytes(var->value.bytes.data, len, fp))
			return -1;

		break;
	default:
		return -2; // Invalid type
	}

	return 0;
}

static inline void variant_free(struct variant *var)
{
	if (!var)
		return;

	switch (var->type) {
	case VARIANT_STRING:
		if (var->value.string)
			free(var->value.string);
		break;
	case VARIANT_BYTES:
		if (var->value.bytes.data && var->value.bytes.len > 0)
			free(var->value.bytes.data);
		break;
	}
}

/*
The inner header (which is called "inner" because it is compressed and encrypted) consists of one or more header fields. A header field consists of an ID t (byte) and a value V (type depends on t). Let s be the size of V in bytes, as Int32. Each header field is stored as follows:
t ‖ s ‖ V.

The following header fields are supported:

Name	ID	Type	Description
End of header	0	–	Indicates the end of the header. Must be present exactly once, as the last header field. The value should be empty.
Inner encryption algorithm	1	Int32	2 = Salsa20, 3 = ChaCha20 (default, recommended). See 'Inner Encryption'.
Inner encryption key (⟳)	2	Byte[]	See 'Inner Encryption'.
Binary content	3	Byte[]	The value is f ‖ C, where f is a flags byte and C is the content of a binary (attachment). The flag 0x01 indicates that the binary content should be protected in the process memory. A binary content is referenced in the XML document by its index in the inner header (the first binary content has index 0, the second one has index 1, etc.).
*/

int buffer_read_int32(int32_t *v, const uint8_t *sp, uint8_t **cp, size_t len)
{
	uint32_t n = 0;
	if ((len - (*cp - sp)) < sizeof(n)) {
		return -1;
	}

	memcpy(&n, *cp, sizeof(n));
	*cp += sizeof(n);
	*v = (int32_t) le32toh(n);
	return 0;
}

int buffer_write_int32(int32_t v, const uint8_t *sp, uint8_t **cp, size_t len)
{
	uint32_t n = 0;
	if ((len - (*cp - sp)) < sizeof(n)) {
		return -1;
	}

	n = (int32_t) le32toh(v);
	memcpy(*cp, &n, sizeof(n));
	*cp += sizeof(n);
	
	return 0;
}

int buffer_read_bytes(void *v, size_t nread, const uint8_t *sp, uint8_t **cp, size_t len)
{
	if ((len - (*cp - sp)) < nread) {
		return -1;
	}

	memcpy(v, *cp, nread);
	*cp += nread;
	return 0;
}

int buffer_write_bytes(void *v, size_t nwrite, const uint8_t *sp, uint8_t **cp, size_t len)
{
	if ((len - (*cp - sp)) < nwrite) {
		return -1;
	}

	memcpy(*cp, v, nwrite);
	*cp += nwrite;
	return 0;
}

static int read_hmac_block(KDBX *db, char **xml_buf, size_t *xml_buf_len, FILE *fp, uint8_t *tx_key, size_t tx_key_len, uint8_t *enc_key, uint64_t block_id)
{
	// First decrypt the data
	int ret = -1;
	uint8_t *content_data = NULL;
	int32_t field_len = 0;
	uint8_t hash[SHA256_DIGEST_LENGTH], hash2[SHA256_DIGEST_LENGTH], hmac_key[SHA512_DIGEST_LENGTH];
	uint8_t *block_hmac_data = NULL, *block_data = NULL, *plaintext = NULL, *plaintextp = NULL;
	size_t block_hmac_data_len = 0;
	ssize_t plaintext_len = 0;

	if (read_bytes(hash2, sizeof(hash2), fp)) {
		return ERR_KDBX_IO;
	}

	if (read_int32(&field_len, fp)) {
		return ERR_KDBX_IO;
	}

	if (field_len == 0) {
		// the last block may have a 0 size
		return 1;
	}

	// we need to allocate extra space in order to verify the hmac hmac data is HMAC(block_id | field_len | block_data)
	block_hmac_data_len = field_len + sizeof(field_len) + sizeof(block_id);
	block_hmac_data = (uint8_t*) malloc(block_hmac_data_len * sizeof(uint8_t));
	block_data = block_hmac_data + sizeof(field_len) + sizeof(block_id);
	if (read_bytes(block_data, field_len, fp)) {
		ret = ERR_KDBX_IO;
		goto decode_block_fail;
	}

	// prepend block id and block size needed to verify the hmac
	memcpy(block_hmac_data, &block_id, sizeof(block_id));
	memcpy(block_hmac_data + sizeof(block_id), &field_len, sizeof(field_len));
	crypto_hmac_key(hmac_key, db->master_salt, tx_key, tx_key_len, block_id);
	hmac_256(hash, hmac_key, sizeof(hmac_key), block_hmac_data, block_hmac_data_len);
	if (memcmp(hash, hash2, SHA256_DIGEST_LENGTH)) {
		ret = ERR_KDBX_VERIFY_HMAC;
		goto decode_block_fail;
	}

	plaintextp = plaintext = (uint8_t*) malloc(field_len * sizeof(uint8_t));
	switch (db->encr) {
	case KDBX_AES256:
	if ((plaintext_len = decrypt_aes256_cbc(plaintext, block_data, field_len, db->iv, enc_key)) <= 0) {
			ret = ERR_KDBX_DECRYPT;
			goto decode_block_fail;
		}
		break;
	case KDBX_CHACHA20:
		if ((plaintext_len = decrypt_chacha20(plaintext, block_data, field_len, db->iv, enc_key)) <= 0) {
			ret = ERR_KDBX_DECRYPT;
			goto decode_block_fail;
		}
		break;
	}

	// on decrypt successfull free the block_hmac_data
	free(block_hmac_data);
	block_hmac_data = NULL;

	// inflate if necessary
	if (db->compressed) {
    	uint8_t *temp = plaintext;
		size_t total = 0, capacity = 0;
    	z_stream strm;
		memset(&strm, 0, sizeof(strm));
		strm.zalloc = Z_NULL;
		strm.zfree = Z_NULL;
		strm.opaque = Z_NULL;
		strm.avail_in = 0;
		strm.next_in = Z_NULL;
		strm.avail_out = 0;
		strm.next_out = Z_NULL;

		ret = inflateInit2(&strm, 16 + MAX_WBITS);
		if (ret != Z_OK) {
			ret = ERR_KDBX_COMPRESSION;
			goto decode_block_fail;
		}

		capacity = plaintext_len;
		plaintext = NULL;
		do {
			strm.avail_in = MIN(plaintext_len - strm.total_in, ZCHUCK);
			if (capacity <= total + strm.avail_in) {
				capacity *= 2;
				plaintext = (uint8_t*) realloc(plaintext, capacity * sizeof(uint8_t));
			}

			strm.next_in = temp + strm.total_in;
			strm.avail_out = capacity - total;			
			strm.next_out = plaintext + total;

			if (inflate(&strm, Z_NO_FLUSH) < Z_OK) {
				inflateEnd(&strm);
				ret = ERR_KDBX_COMPRESSION;
				goto decode_block_fail;
			}
			
			total = strm.total_out;

		} while (strm.avail_out == 0);

		plaintext_len = total;
		free(temp);

		inflateEnd(&strm);
	}

	plaintextp = plaintext;
	while ((plaintextp - plaintext) < plaintext_len) {
		uint8_t type = *(plaintextp++);
		if (buffer_read_int32(&field_len, plaintext, &plaintextp, plaintext_len)) {
			ret = ERR_KDBX_INVALID;
			goto decode_block_fail;
		}

		if (type == 0) {
			break;
		}

		switch (type) {
		case 1:
			if (buffer_read_int32(&field_len, plaintext, &plaintextp, plaintext_len)) {
				ret = ERR_KDBX_INVALID;
				goto decode_block_fail;
			}
			if (field_len < KDBX_SALSA20 || field_len > KDBX_CHACHA20) {
				ret = ERR_KDBX_UNSUPPORTED_ENC_ALGORITHM;
				goto decode_block_fail;		
			}
			db->inner_encr = field_len;
			break;
		case 2:
			db->inner_key = (uint8_t*) realloc(db->inner_key, field_len * sizeof(uint8_t));
			db->inner_key_len = field_len;
			if (buffer_read_bytes(db->inner_key, field_len, plaintext, &plaintextp, plaintext_len)) {
				ret = ERR_KDBX_INVALID;
				goto decode_block_fail;
			}
			break;
		case 3:
			content_data = (uint8_t*) malloc(field_len * sizeof(uint8_t));
			
			if (buffer_read_bytes(content_data, field_len, plaintext, &plaintextp, plaintext_len)) {
				ret = ERR_KDBX_INVALID;
				goto decode_block_fail;
			}
			if (add_inner_content(db, block_id, content_data, field_len)) {
				ret = ERR_KDBX_INVALID;
				goto decode_block_fail;
			}
			break;
		}
	}

	// Read the XML data
	field_len = plaintext_len - (plaintextp - plaintext);
	*xml_buf = (char*) realloc(*xml_buf, (*xml_buf_len + field_len) * sizeof(char));
	if (buffer_read_bytes(*xml_buf + *xml_buf_len, field_len, plaintext, &plaintextp, plaintext_len)) {
		ret = ERR_KDBX_INVALID;
		goto decode_block_fail;
	}

	*xml_buf_len += field_len;

	ret = 0;
decode_block_fail:
	free(block_hmac_data);
	free(plaintext);
	return ret;
}

static xmlNode *xml_next_elem(xmlNode *parent, const char *name)
{
	xmlNode *cur_node = NULL;
	if (!parent->next) {
		return NULL;
	}

    for (cur_node = parent->next; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE && !xmlStrcmp(cur_node->name, (xmlChar*) name)) {
			return cur_node;
        }
    }

	return NULL;
}

static xmlNode *xml_first_child(xmlNode *parent, const char *name)
{
	xmlNode *cur_node = NULL;
	if (!parent->children) {
		return NULL;
	}

	for (cur_node = parent->children; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE && !xmlStrcmp(cur_node->name, (xmlChar*) name)) {
			return cur_node;
        }
    }
	
	return NULL;
}

static time_t decode_xml_time(xmlNode *node)
{
	if (!node->children) {
		return 0;
	}

	xmlChar *tstr = xmlNodeGetContent(node->children);
	if (!tstr) {
		return 0;
	}

	int tlen = strlen((char*) tstr);
	time_t time = 0;
	if (b64_decode((uint8_t*) &time, sizeof(time), (char*) tstr, tlen) < 8) {
		xmlFree(tstr);
		return 0;
	}
	
	xmlFree(tstr);
	time = le64toh(time);
	return time - KEEPASS_EPOCH; 
}

static int read_xml_times(KDBXTimeInfo *tinfo, xmlNode *root)
{
	xmlNode *tnode;
	tnode = xml_first_child(root, "LastModificationTime");
	if (tnode) {
		tinfo->last_mod = decode_xml_time(tnode);	
	}
	tnode = xml_first_child(root, "CreationTime");
	if (tnode) {
		tinfo->creation = decode_xml_time(tnode);	
	}
	tnode = xml_first_child(root, "Expires");
	tinfo->expiration = 0;
	if (tnode) {
		xmlChar *tstr = xmlNodeGetContent(tnode->children);
		tinfo->expiration = tstr && !xmlStrcmp(tstr, (xmlChar*) "True");
		if (tinfo->expiration) {
			tnode = xml_first_child(root, "ExpiryTime");
			if (tnode)
				tinfo->expiration = decode_xml_time(tnode);
		}	
	}

	return 0;
}

static int read_xml_entry_values(KDBXEntry *entry, EVP_CIPHER_CTX *rnd, xmlNode *xml_entry)
{
	ssize_t len;
	int protect = 0;
	xmlNode *xml_value, *xml_key, *xml_obj;
	xmlChar *txt1 = NULL, *txt2 = NULL, *temp;

	for (xml_value = xml_first_child(xml_entry, "String"); xml_value; xml_value = xml_next_elem(xml_value, "String")) {
		xml_key = xml_first_child(xml_value, "Key");
		if (!xml_key) {
			return ERR_KDBX_INVALID_XML;
		}

		xml_obj = xml_first_child(xml_value, "Value");
		if (!xml_obj) {
			return ERR_KDBX_INVALID_XML;
		}

		txt1 = xmlNodeGetContent(xml_key->children);

		txt2 = xmlGetProp(xml_obj, (xmlChar*) "Protected");
		protect = txt2 && !xmlStrcmp(txt2, (xmlChar*) "True");
		xmlFree(txt2);
		
		txt2 = xmlNodeGetContent(xml_obj->children);
		if (protect) {
			temp = txt2;
			len = strlen((char*) temp);
			txt2 = (xmlChar*) malloc((B64_DECODED_LEN(len) + 1) * sizeof(xmlChar));
			
			len = b64_decode(txt2, B64_DECODED_LEN(len) + 1, (char*) temp, len);
			xmlFree(temp);
			if (len < 0) {
				goto read_value_end;
			}

			if (rnd_stream_xor(rnd, txt2, len)) {
				goto read_value_end;
			}
		}
		
		if (entry) {
			entry_put_value(entry, (char*) txt1, (char*) txt2, protect);
		}

read_value_end:
		xmlFree(txt1);
		xmlFree(txt2);
	}

	return 0;
}

static int read_xml_group(KDBX *db, EVP_CIPHER_CTX *rnd, xmlNode *root)
{
	int protect = 0;
	xmlNode *xml_entry, *xml_value, *xml_hist, *xml_key, *xml_obj;
	KDBXGroup *group = NULL;
	KDBXEntry *entry = NULL;

	xml_obj = xml_first_child(root, "Name");
	if (!xml_obj) {
		return ERR_KDBX_INVALID_XML;
	}

	// Read group name
	xmlChar *txt1 = NULL;
	group = kdbx_add_group(db, (char*) (txt1 = xmlNodeGetContent(xml_obj->children)));
	xmlFree(txt1);
	
	xml_obj = xml_first_child(root, "Times");
	if (xml_obj) {
		if (read_xml_times(&group->time_info, xml_obj)) {
			return ERR_KDBX_INVALID_XML;
		}
	}

	for (xml_entry = xml_first_child(root, "Entry"); xml_entry; xml_entry = xml_next_elem(xml_entry, "Entry")) {
		entry = kdbx_group_add_entry(group, 0);
		xml_obj = xml_first_child(xml_entry, "Times");
		if (xml_obj) {
			if (read_xml_times(&entry->time_info, xml_obj)) {
				return ERR_KDBX_INVALID_XML;
			}
		}

		if (read_xml_entry_values(entry, rnd, xml_entry)) {
			return ERR_KDBX_INVALID_XML;
		}

		/*
			Read the history value
			NOTE: we discard this but to keep the random stream flow
			correctly we need to decode it anyway
		*/
		xml_value = xml_first_child(xml_entry, "History");
		if (xml_value) {
			for (xml_hist = xml_first_child(xml_value, "Entry"); xml_hist; xml_hist = xml_next_elem(xml_hist, "Entry")) {
				read_xml_entry_values(NULL, rnd, xml_hist);
			}
		}
	}

	/*
	 * Reads nested groups: groups are not stored into a tree structure like in KeePassXC, 
	 * keepassxt stores groups in a plain list even if the groups are nested
	*/
	for (xml_entry = xml_first_child(root, "Group"); xml_entry; xml_entry = xml_next_elem(xml_entry, "Group")) {
		if (read_xml_group(db, rnd, xml_entry)) {
			return ERR_KDBX_INVALID_XML;
		}
	}

	return 0;
}

int kdbx_read(KDBX *db, const char *fpath, const char *password)
{
	FILE *fp = fopen(fpath, "rb");
	if (!fp) {
		return -1;
	}

	int ret = 0;
	int32_t len = 0;
	uint32_t sig = 0;
	xmlDoc *doc = NULL;
	if (read_uint32(&sig, fp)) {
		ret = ERR_KDBX_IO;
		goto read_fail;
	}
	if (sig != SIGNATURE_1) {
		return -2;
	}

	if (read_uint32(&sig, fp)) {
		ret = ERR_KDBX_IO;
		goto read_fail;
	}

	if (sig != SIGNATURE_2) {
		return -2;
	}

	if (read_uint32(&sig, fp)) {
		ret = ERR_KDBX_IO;
		goto read_fail;
	}

	db->version_major = (uint32_t) ((sig & 0xffff0000) >> 16);
	db->version_minor = (uint32_t) (sig & 0x0000ffff);

	int header_type = 0;
	uint8_t uuid[UUID_LEN];
	uint16_t vardict_version = 0;
	struct variant var;
	do {
		header_type = fgetc(fp);
		if (header_type == EOF) {
			ret = ERR_KDBX_IO;
			goto read_fail;
		}
		
		if (read_int32(&len, fp)) {
			ret = ERR_KDBX_IO;
			goto read_fail;
		}

		switch (header_type) {
		case 0:
			if (read_uint32(&sig, fp)) {
				ret = ERR_KDBX_IO;
				goto read_fail;
			}
			if (sig != HEADER_END) {
				return -2;
			}

			break;
		case 2: // Encryption Algo -> Compare UUIDS
			if (read_bytes(uuid, sizeof(uuid), fp)) {
				ret = ERR_KDBX_IO;
				goto read_fail;
			}
			if (!memcmp(uuid, AES256_UUID, UUID_LEN)) {
				db->encr = KDBX_AES256;
			} else if (!memcmp(uuid, CHACHA20_UUID, UUID_LEN)) {
				db->encr = KDBX_CHACHA20;
			} else {
				ret = ERR_KDBX_UNSUPPORTED_ENC_ALGORITHM;
				goto read_fail;
			}
			break;
		case 3: // Compression
			if (read_int32(&db->compressed, fp)) {
				ret = ERR_KDBX_IO;
				goto read_fail;
			}
			break;
		case 4: // Master salt
			if (read_bytes(db->master_salt, sizeof(db->master_salt), fp)) {
				ret = ERR_KDBX_IO;
				goto read_fail;
			}
			break;
		case 7:
			if (read_bytes(db->iv, len, fp)) {
				ret = ERR_KDBX_IO;
				goto read_fail;
			}
			break;
		case 11:
			if (read_uint16(&vardict_version, fp)) {
				ret = ERR_KDBX_IO;
				goto read_fail;
			}
			while ((ret = read_variant(&var, fp)) == 0) {
				if (!strcmp(var.name, "$UUID")) {
					if (var.value.bytes.len != UUID_LEN) {
						variant_free(&var);
						ret = ERR_KDBX_IO;
						goto read_fail;
					}

					if (!memcmp(var.value.bytes.data, KDF_AES_UUID, UUID_LEN)) {
						db->kdf_type = KDBX_KDF_AES;
					} else if (!memcmp(var.value.bytes.data, KDF_ARGON_2D_UUID, UUID_LEN)) {
						db->kdf_type = KDBX_KDF_ARGON_2D;				
					} else if (!memcmp(var.value.bytes.data, KDF_ARGON_2ID_UUID, UUID_LEN)) {
						db->kdf_type = KDBX_KDF_ARGON_2ID;
					} else {
						variant_free(&var);
						ret = ERR_KDBX_UNSUPPORTED_KDF_ALGORITHM;
						goto read_fail;
					}	
				} else if (!strcmp(var.name, "S")) {
					db->kdf_salt_len = var.value.bytes.len;
					db->kdf_salt = var.value.bytes.data;
					var.value.bytes.data = NULL;
				} else if (!strcmp(var.name, "R")) {
					db->kdf.kdf_aes.rounds = var.value.uint64;
				} else if (!strcmp(var.name, "V")) {
					db->kdf.kdf_argon2.version = var.value.uint32;
				} else if (!strcmp(var.name, "I")) {
					db->kdf.kdf_argon2.iterations = var.value.uint64;
				} else if (!strcmp(var.name, "M")) {
					db->kdf.kdf_argon2.memory = var.value.uint64;
				} else if (!strcmp(var.name, "P")) {
					db->kdf.kdf_argon2.parallelism = var.value.uint32;
				}
				
				variant_free(&var);
			}

			break;
		case 12:
			// Skip plugin custom data as is not supported
			if (read_uint16(&vardict_version, fp)) {
				ret = ERR_KDBX_IO;
				goto read_fail;
			}
			while ((ret = read_variant(&var, fp)) == 0)
				variant_free(&var);

			break;
		default:
			// Skip not supported fields
			while (len--) {
				if (fgetc(fp) == EOF)
					return -1;
			}
		}
	} while (header_type);
	
	/*
		* In KDBX version4, the header integrity is verified through a SHA-256 hash and an hmac
		* the hmac value is computed as follows:
		* Let R be the SHA-256 hash of the concatenation of the components of the master key that the user has provided (each optional, in the following order):
		* SHA-256 hash of the master password (encoded using UTF-8).
		* Key stored in a key file.
		* Key provided by a key provider plugin.
		* Key protected using the Windows user account (DPAPI). (keepassxt is UNIX only and does not support this component)
		* Let T be the result of transforming R using a key derivation function. The function and parameters for it are stored in the header.	
		* With T and the master salt/seed S (stored in the header), the final keys can be computed:
		* If the encryption algorithm needs a key smaller than 256 bits, the key consists of the first bytes of SHA-256(S ‖ T).
		* The key for the HMAC-SHA-256 hash of the header is:
		* 	SHA-512(0xFFFFFFFFFFFFFFFF ‖ SHA-512(S ‖ T ‖ 0x01)).
		* The key for the HMAC-SHA-256 hash of the i-th block (zero-based index, type UInt64) of the HMAC-protected block stream is:
		* 	SHA-512(i ‖ SHA-512(S ‖ T ‖ 0x01)).
		*/

	uint8_t tx_key[KDF_DERIVE_LEN];
	size_t tx_key_len = KDF_DERIVE_LEN;
	if (transform_key(db, password, tx_key)) {
		ret = ERR_KDBX_KDF_TRANSFORM;
		goto read_fail;
	}

	uint8_t hash[SHA256_DIGEST_LENGTH], hash2[SHA256_DIGEST_LENGTH];
	long header_len = ftell(fp);

	uint8_t *header_data = (uint8_t*) malloc(header_len * sizeof(uint8_t));
	rewind(fp);
	if (read_bytes(header_data, header_len, fp)) {
		free(header_data);
		ret = ERR_KDBX_IO;
		goto read_fail;
	}

	if (read_bytes(hash2, sizeof(hash2), fp)) {
		free(header_data);
		ret = ERR_KDBX_IO;
		goto read_fail;
	}

	SHA256(header_data, header_len, hash);
	if (memcmp(hash, hash2, sizeof(hash2))) {
		free(header_data);
        ret = ERR_KDBX_VERIFY_HASH;
		goto read_fail;
	}

	// reads the hmac
	if (read_bytes(hash2, sizeof(hash2), fp)) {
		free(header_data);
		ret = ERR_KDBX_VERIFY_HASH;
		goto read_fail;
	}

	uint8_t hmac_key[SHA512_DIGEST_LENGTH];
	crypto_hmac_key(hmac_key, db->master_salt, tx_key, tx_key_len, 0xFFFFFFFFFFFFFFFF);
	hmac_256(hash, hmac_key, sizeof(hmac_key), header_data, header_len);
	free(header_data);
	if (memcmp(hash, hash2, SHA256_DIGEST_LENGTH)) {
		ret = ERR_KDBX_VERIFY_HMAC;
		goto read_fail;
	}

	/* The subsequent data is divided in blocks. Each block is composed as follows:
		* - the block HMAC (32 bytes)
		* - the size of the block (int32 4 bytes)
		* - the block data: contains the encrypted inner header + XML payload, if the compress flag is set to 1
		*   then the decrypted data must be inflated before reading the actual data
		*/

	uint8_t final_key[SHA256_DIGEST_LENGTH];
	crypto_final_key(final_key, db->master_salt, tx_key, tx_key_len);

	uint64_t block_id;
	char *xml_buf = NULL;
	size_t xml_buf_len = 0;
	for (block_id = 0; !feof(fp); block_id++) {
		// reads the hmac of the block
		ret = read_hmac_block(db, &xml_buf, &xml_buf_len, fp, tx_key, tx_key_len, final_key, block_id);
		if (ret == 1) {
			break;
		} else if (ret < 0) {
			free(xml_buf);
			return ret;
		}
	}

	doc = xmlReadMemory(xml_buf, xml_buf_len, "keepass.xml", NULL, 0);
	free(xml_buf);
	if (!doc) {
		ret = ERR_KDBX_INVALID_XML;
		goto read_fail;
	}

	xmlNode *root;
	root = xmlDocGetRootElement(doc);
	if (!root) {
		ret = ERR_KDBX_INVALID_XML;
		goto read_fail;
	}

	root = xml_first_child(root, "Root");
	if (!root) {
		printf("xml fail1 read Root\n");
		ret = ERR_KDBX_INVALID_XML;
		goto read_fail;
	}
	root = xml_first_child(root, "Group");
	if (!root) {
		printf("xml fail2 read Group\n");
		ret = ERR_KDBX_INVALID_XML;
		goto read_fail;
	}

	EVP_CIPHER_CTX *rnd = rnd_stream_new(-1, db->inner_key, db->inner_key_len);
	if ((ret = read_xml_group(db, rnd, root))) {
		rnd_stream_close(rnd);
		goto read_fail;
	}

	rnd_stream_close(rnd);

	ret = 0;
read_fail:
	xmlFreeDoc(doc);
	fclose(fp);
	// Read the payload till the end;
	return ret;
}

void zerr(int ret, int line)
{
    switch (ret) {
    case Z_ERRNO:
        if (ferror(stdin))
            fputs("error reading stdin\n", stderr);
        if (ferror(stdout))
            fputs("error writing stdout\n", stderr);
        break;
    case Z_STREAM_ERROR:
        fputs("invalid compression level\n", stderr);
        break;
    case Z_DATA_ERROR:
        fputs("invalid or incomplete deflate data\n", stderr);
        break;
    case Z_MEM_ERROR:
        fputs("out of memory\n", stderr);
        break;
    case Z_VERSION_ERROR:
        fputs("zlib version mismatch!\n", stderr);
    }
}

/* ================================= WRITE KDBX ==================================== */
//FIXME introduce a buffer struct that handles zlib inflate/deflate automatically, consuming less memory using smaller chunks
static int write_hmac_block(KDBX *db, char *xml_buf, size_t xml_buf_len, FILE *fp, uint8_t *tx_key, size_t tx_key_len, uint8_t *enc_key, uint64_t block_id)
{
	int ret = -1;
	
	int32_t block_data_len = 0;
	size_t i, plaintext_len = 0;

	uint8_t hash[SHA256_DIGEST_LENGTH], hmac_key[SHA512_DIGEST_LENGTH];
	uint8_t *block_hmac_data = NULL, *block_data = NULL;
	uint8_t *plaintext = NULL;

	if (xml_buf_len) {
		plaintext_len = xml_buf_len + 3 * (1 + sizeof(int32_t)) + sizeof(int32_t) + db->inner_key_len;
		for (i = 0; i < db->inner_contents_len; i++) {
			if (db->inner_contents[i].content_len)
				plaintext_len += 1 + sizeof(int32_t) + db->inner_contents[i].content_len;
		}

		plaintext = (uint8_t*) malloc(plaintext_len * sizeof(uint8_t));
		uint8_t *plaintextp = plaintext;

		(*plaintextp++) = 1;
		if (buffer_write_int32(sizeof(int32_t), plaintext, &plaintextp, plaintext_len)) {
			ret = ERR_KDBX_INVALID;
			goto encode_block_fail;
		}
		if (buffer_write_int32(db->inner_encr, plaintext, &plaintextp, plaintext_len)) {
			ret = ERR_KDBX_INVALID;
			goto encode_block_fail;
		}

		(*plaintextp++) = 2;
		if (buffer_write_int32(db->inner_key_len, plaintext, &plaintextp, plaintext_len)) {
			ret = ERR_KDBX_INVALID;
			goto encode_block_fail;
		}
		if (buffer_write_bytes(db->inner_key, db->inner_key_len, plaintext, &plaintextp, plaintext_len)) {
			ret = ERR_KDBX_INVALID;
			goto encode_block_fail;
		}
		for (i = 0; i < db->inner_contents_len; i++) {
			if (db->inner_contents[i].blockid != block_id)
				continue;

			(*plaintextp++) = 3;
			if (buffer_write_int32(db->inner_contents[i].content_len, plaintext, &plaintextp, plaintext_len)) {
				ret = ERR_KDBX_INVALID;
				goto encode_block_fail;
			}
			if (buffer_write_bytes(db->inner_contents[i].content, db->inner_contents[i].content_len, plaintext, &plaintextp, plaintext_len)) {
				ret = ERR_KDBX_INVALID;
				goto encode_block_fail;
			}
		}

		(*plaintextp++) = 0;
		if (buffer_write_int32(0, plaintext, &plaintextp, plaintext_len)) {
			ret = ERR_KDBX_INVALID;
			goto encode_block_fail;
		}

		if (buffer_write_bytes(xml_buf, xml_buf_len, plaintext, &plaintextp, plaintext_len)) {
			ret = ERR_KDBX_INVALID;
			goto encode_block_fail;
		}
	}

	if (plaintext_len && db->compressed) {
		//not implemented for now
		int flush;
		uint8_t *temp = plaintext;
		size_t capacity = 0, total = 0;
    		z_stream strm;
		memset(&strm, 0, sizeof(strm));
		strm.zalloc = Z_NULL;
    		strm.zfree = Z_NULL;
    		strm.opaque = Z_NULL;
		// (strm, level, method, windowBits, memLevel, strategy)
    		ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY);
    		if (ret != Z_OK) {
			zerr(ret, __LINE__);
        		ret = ERR_KDBX_COMPRESSION;
			goto encode_block_fail;
		}

		plaintext = NULL;
		do {
			strm.avail_in = MIN(plaintext_len - strm.total_in, ZCHUCK);
			strm.next_in = temp + strm.total_in;
			if (strm.avail_in >= capacity) {
				capacity += strm.avail_in + strm.avail_in / 4;
				plaintext = (uint8_t*) realloc(plaintext, capacity);
			}

			flush = strm.avail_in ? Z_NO_FLUSH : Z_FINISH;

			strm.avail_out = capacity - total;
			strm.next_out = plaintext + total;

			if ((ret = deflate(&strm, flush)) < Z_OK) {
				(void)deflateEnd(&strm);
				zerr(ret, __LINE__);
				ret = ERR_KDBX_COMPRESSION;
				goto encode_block_fail;
			}

			total = strm.total_out;
		} while (ret != Z_STREAM_END);

		(void) deflateEnd(&strm);
    	
		free(temp);
		plaintext_len = total;
	}

	// we need to allocate extra space in order to verify the hmac hmac data is HMAC(block_id | field_len | block_data)
	block_hmac_data = (uint8_t*) malloc((sizeof(block_id) + sizeof(int32_t) + plaintext_len + 512) * sizeof(uint8_t));
	block_data = block_hmac_data + sizeof(block_id) + sizeof(int32_t);

	if (plaintext_len) {
		switch (db->encr) {
		case KDBX_AES256:
		if ((block_data_len = encrypt_aes256_cbc(block_data, plaintext, plaintext_len, db->iv, enc_key)) <= 0) {
				ret = ERR_KDBX_ENCRYPT;
				goto encode_block_fail;
			}
			break;
		case KDBX_CHACHA20:
			if ((block_data_len = encrypt_chacha20(block_data, plaintext, plaintext_len, db->iv, enc_key)) <= 0) {
				ret = ERR_KDBX_ENCRYPT;
				goto encode_block_fail;
			}
			break;
		}
	}

	memcpy(block_hmac_data, &block_id, sizeof(block_id));
	memcpy(block_hmac_data + sizeof(block_id), &block_data_len, sizeof(block_data_len));

	crypto_hmac_key(hmac_key, db->master_salt, tx_key, tx_key_len, block_id);
	hmac_256(hash, hmac_key, sizeof(hmac_key), block_hmac_data, sizeof(block_id) + sizeof(int32_t) + block_data_len);
	if (write_bytes(hash, sizeof(hash), fp)) {
		ret = ERR_KDBX_IO;
		goto encode_block_fail;
	}
	if (write_int32(block_data_len, fp)) {
		ret = ERR_KDBX_IO;
		goto encode_block_fail;
	}
	if (block_data_len && write_bytes(block_data, block_data_len, fp)) {
		ret = ERR_KDBX_IO;
		goto encode_block_fail;
	}

	ret = 0;
encode_block_fail:
	free(block_hmac_data);
	free(plaintext);
	return ret;
}

static int write_xml_times(KDBXTimeInfo *info, xmlNode *root)
{
	xmlNode *child;
	xmlChar out[B64_ENCODED_LEN(8) + 1];
	uint64_t time = 0;
	time = info->last_mod + KEEPASS_EPOCH;
	if (b64_encode((char*) out, sizeof(out), (uint8_t*) &time, sizeof(time)) < 0) {
		return -1;
	}
	child = xmlNewChild(root, NULL, BAD_CAST "LastModificationTime", NULL);
	xmlNodeSetContent(child, BAD_CAST out);

	time = info->creation + KEEPASS_EPOCH;
	if (b64_encode((char*) out, sizeof(out), (uint8_t*) &time, sizeof(time)) < 0) {
		return -1;
	}
	child = xmlNewChild(root, NULL, BAD_CAST "CreationTime", NULL);
	xmlNodeSetContent(child, BAD_CAST out);

	child = xmlNewChild(root, NULL, BAD_CAST "Expires", NULL);
	xmlNodeSetContent(child, BAD_CAST (info->expiration ? "True" : "False"));
	if (info->expiration > 0) {
		time = info->expiration + KEEPASS_EPOCH;
		if (b64_encode((char*) out, sizeof(out), (uint8_t*) &time, sizeof(time)) < 0) {
			return -1;
		}
		child = xmlNewChild(root, NULL, BAD_CAST "ExpiryTime", NULL);
		xmlNodeSetContent(child, BAD_CAST out);
	}	

	return 0;
}

static int write_xml_group(xmlNode *root, EVP_CIPHER_CTX *rnd, KDBXGroup *group)
{
	size_t i, j;
	ssize_t len;
	xmlChar *txt1, *temp;
	xmlNode *xml_entry, *xml_value, *xml_obj;
	KDBXEntry *entry = NULL;

	xml_obj = xmlNewChild(root, NULL, BAD_CAST "Name", NULL);
	xmlNodeSetContent(xml_obj, BAD_CAST group->name);
	
	xml_obj = xmlNewChild(root, NULL, BAD_CAST "Times", NULL);
	write_xml_times(&group->time_info, xml_obj);
	for (i = 0; i < group->entries_count; i++) {
		entry = &group->entries[i];

		xml_entry = xmlNewChild(root, NULL, BAD_CAST "Entry", NULL);
		xml_obj = xmlNewChild(xml_entry, NULL, BAD_CAST "Times", NULL);
		write_xml_times(&entry->time_info, xml_obj);

		for (j = 0; j < entry->values_count; j++) {
			xml_value = xmlNewChild(xml_entry, NULL, BAD_CAST "String", NULL);
			
			xml_obj = xmlNewChild(xml_value, NULL, BAD_CAST "Key", NULL);
			xmlNodeSetContent(xml_obj, BAD_CAST entry->values[j].key);

			xml_obj = xmlNewChild(xml_value, NULL, BAD_CAST "Value", NULL);
			
			txt1 = (xmlChar*) str_clone(entry->values[j].value);
			if (entry->values[j].protect) {
				xmlSetProp(xml_obj, BAD_CAST "Protected", BAD_CAST "True");
				
				temp = txt1;
				len = strlen((char*) temp);
				if (rnd_stream_xor(rnd, temp, len)) {
					xmlFree(txt1);
					return ERR_KDBX_INVALID_XML;					
				}
				
				txt1 = (xmlChar*) malloc((B64_ENCODED_LEN(len) + 1) * sizeof(xmlChar));
				if (b64_encode((char*) txt1, B64_ENCODED_LEN(len) + 1, temp, len) < 0) {
					xmlFree(temp);
					xmlFree(txt1);
					return ERR_KDBX_INVALID_XML;					
				}
			}

			xmlNodeSetContent(xml_obj, txt1);
			xmlFree(txt1);
		}
	}

	return 0;
}

int kdbx_write(KDBX *db, const char *fpath, const char *password)
{
	FILE *fp = fopen(fpath, "wb+");
	if (!fp) {
		return -1;
	}

	int i, ret = -1;
	uint32_t val;
	int32_t len;
	if (write_uint32(SIGNATURE_1, fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	if (write_uint32(SIGNATURE_2, fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}

	val = (db->version_major << 16) | (db->version_minor & 0x0000ffff);
	if (write_uint32(val, fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}

	if (fputc(2, fp) == EOF) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	if (write_int32(UUID_LEN, fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	switch (db->encr) {
	case KDBX_AES256:
		if (write_bytes((uint8_t*) AES256_UUID, UUID_LEN, fp)) {
			ret = ERR_KDBX_IO;
			goto write_fail;
		}
		break;
	case KDBX_CHACHA20:
		if (write_bytes((uint8_t*) CHACHA20_UUID, UUID_LEN, fp)) {
			ret = ERR_KDBX_IO;
			goto write_fail;
		}
		break;
	}

	if (fputc(3, fp) == EOF) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	if (write_int32(sizeof(db->compressed), fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	if (write_int32(db->compressed, fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}

	if (fputc(4, fp) == EOF) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	if (write_int32(sizeof(db->master_salt), fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	if (write_bytes(db->master_salt, sizeof(db->master_salt), fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}

	if (fputc(7, fp) == EOF) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	if (write_int32(IV_LEN(db->encr), fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	if (write_bytes(db->iv, IV_LEN(db->encr), fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}

	if (fputc(11, fp) == EOF) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	// calculate the size of the vardict
	
	len = sizeof(uint16_t) + VARIANT_SIZE("$UUID", UUID_LEN) + VARIANT_SIZE("S", db->kdf_salt_len) + 1;
	switch (db->kdf_type) {
	case KDBX_KDF_AES:
		len += VARIANT_SIZE("R", sizeof(uint64_t));
		break;
	case KDBX_KDF_ARGON_2D:
	case KDBX_KDF_ARGON_2ID:
		len += VARIANT_SIZE("V", sizeof(uint32_t));
		len += VARIANT_SIZE("I", sizeof(uint64_t));
		len += VARIANT_SIZE("M", sizeof(uint64_t));
		len += VARIANT_SIZE("P", sizeof(uint32_t));
		break;
	}
	if (write_int32(len, fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	if (write_uint16(VARIANT_DICT_VERSION, fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}

	struct variant var;
	switch (db->kdf_type) {
	case KDBX_KDF_AES:
		VARIANT_SET_BYTES(var, "$UUID", KDF_AES_UUID, UUID_LEN);
		break;
	case KDBX_KDF_ARGON_2D:
		VARIANT_SET_BYTES(var, "$UUID", KDF_ARGON_2D_UUID, UUID_LEN);
		break;
	case KDBX_KDF_ARGON_2ID:
		VARIANT_SET_BYTES(var, "$UUID", KDF_ARGON_2ID_UUID, UUID_LEN);
		break;
	}
	if (write_variant(&var, fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}

	VARIANT_SET_BYTES(var, "S", db->kdf_salt, db->kdf_salt_len);
	if (write_variant(&var, fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}

	switch (db->kdf_type) {
	case KDBX_KDF_AES:
		VARIANT_SET_UINT64(var, "R", db->kdf.kdf_aes.rounds);
		if (write_variant(&var, fp)) {
			ret = ERR_KDBX_IO;
			goto write_fail;
		}
		break;
	case KDBX_KDF_ARGON_2D:
	case KDBX_KDF_ARGON_2ID:
		VARIANT_SET_UINT64(var, "I", db->kdf.kdf_argon2.iterations);
		if (write_variant(&var, fp)) {
			ret = ERR_KDBX_IO;
			goto write_fail;
		}
		VARIANT_SET_UINT64(var, "M", db->kdf.kdf_argon2.memory);
		if (write_variant(&var, fp)) {
			ret = ERR_KDBX_IO;
			goto write_fail;
		}
		VARIANT_SET_UINT32(var, "P", db->kdf.kdf_argon2.parallelism);
		if (write_variant(&var, fp)) {
			ret = ERR_KDBX_IO;
			goto write_fail;
		}
		VARIANT_SET_UINT32(var, "V", db->kdf.kdf_argon2.version);
		if (write_variant(&var, fp)) {
			ret = ERR_KDBX_IO;
			goto write_fail;
		}
		break;
	}

	VARIANT_SET_END(var);
	if (write_variant(&var, fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}

	if (fputc(0, fp) == EOF) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	if (write_int32(sizeof(uint32_t), fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	if (write_uint32(HEADER_END, fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}

	uint8_t hash[SHA256_DIGEST_LENGTH];
	uint8_t tx_key[KDF_DERIVE_LEN];
	size_t tx_key_len = KDF_DERIVE_LEN;
	if (transform_key(db, password, tx_key)) {
		ret = ERR_KDBX_KDF_TRANSFORM;
		goto write_fail;
	}

	long header_len = ftell(fp);
	uint8_t *header_data = (uint8_t*) malloc(header_len * sizeof(uint8_t));
	rewind(fp);
	if (read_bytes(header_data, header_len, fp)) {
		free(header_data);
		ret = ERR_KDBX_IO;
		goto write_fail;
	}
	fseek(fp, 0, SEEK_END);
	
	SHA256(header_data, header_len, hash);
	if (write_bytes(hash, sizeof(hash), fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}

	uint8_t hmac_key[SHA512_DIGEST_LENGTH];
	crypto_hmac_key(hmac_key, db->master_salt, tx_key, tx_key_len, 0xFFFFFFFFFFFFFFFF);
	hmac_256(hash, hmac_key, sizeof(hmac_key), header_data, header_len);
	free(header_data);
	if (write_bytes(hash, sizeof(hash), fp)) {
		ret = ERR_KDBX_IO;
		goto write_fail;
	}

	xmlDoc *doc = NULL;
	xmlNode *root, *xml_root, *xml_group;

	doc = xmlNewDoc(BAD_CAST "1.0");
    	root = xmlNewNode(NULL, BAD_CAST "KeePassFile");
   	xmlDocSetRootElement(doc, root);

	xml_root = xmlNewChild(root, NULL, BAD_CAST "Meta", NULL);
	xml_root = xmlNewChild(xml_root, NULL, BAD_CAST "Generator", NULL);
	xmlNodeSetContent(xml_root, BAD_CAST KDBX_GENERATOR);

	xml_root = xmlNewChild(root, NULL, BAD_CAST "Root", NULL);
	if (db->groups_count) {
		EVP_CIPHER_CTX *rnd = rnd_stream_new(-1, db->inner_key, db->inner_key_len);
		xml_root = xmlNewChild(xml_root, NULL, BAD_CAST "Group", NULL);
		write_xml_group(xml_root, rnd, db->groups + 0);

		for (i = 1; i < db->groups_count; i++) {
			xml_group = xmlNewChild(xml_root, NULL, BAD_CAST "Group", NULL);
			write_xml_group(xml_group, rnd, db->groups + i);
		}
		
		rnd_stream_close(rnd);
	}

	xmlChar *xml_buf = NULL;
	int xml_buf_len = 0, l = 0, bsize = 0;
	xmlDocDumpFormatMemory(doc, &xml_buf, &xml_buf_len, 0);
	xmlFreeDoc(doc);

	uint8_t final_key[SHA256_DIGEST_LENGTH];
	crypto_final_key(final_key, db->master_salt, tx_key, tx_key_len);

	// Write blocks
	for (i = 0, l = 0; l < xml_buf_len; l += MAX_HMAC_BLOCK_LEN, i++) {
		bsize = (xml_buf_len - l) > MAX_HMAC_BLOCK_LEN ? 
			MAX_HMAC_BLOCK_LEN : (xml_buf_len - l);

		ret = write_hmac_block(db, ((char*) xml_buf) + l, bsize, fp, 
			tx_key, tx_key_len, final_key, i);
		if (ret) {
			goto write_fail;
		}
		
	}

	if ((ret = write_hmac_block(db, NULL, 0, fp, tx_key, tx_key_len, final_key, i))) {
		goto write_fail;
	}

	xmlFree(xml_buf);

	ret = 0;
write_fail:
	fclose(fp);
	return ret;
}


