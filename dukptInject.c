/**
 * FEIG ELECTRONIC Contactless Demo
 *
 * Copyright (C) 2016 FEIG ELECTRONIC GmbH
 *
 * This software is the confidential and proprietary information of
 * FEIG ELECTRONIC GmbH ("Confidential Information"). You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered
 * into with FEIG ELECTRONIC GmbH.
 */

/*
 * This program injects a test DUKPT Initial Key into a cVEND Development
 * device.  Note that this will not work for secure production devices.  To
 * discuss options for injection cryptographic keys into production devices
 * please contact cvend-support@feig.de
 *
 * Build as follows:
 * arm-linux-gcc -Wall -Werror inject-dukpt-ik.c -o inject-dukpt-ik -lfepkcs11 \
 *		 -lcrypto
 * fesign --module opensc-pkcs11.so --pin 648219 --slotid 1 --keyid 00a0 \
 *	  --infile inject-dukpt-ik
 *	  all good
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <feig/fepkcs11.h>
#include <feig/memset_s.h>

#define ARRAY_SIZE(x) (sizeof(x)/sizeof(*(x)))
#define hexdigit(x) ((x)>='A'?(x)>='a'?(x)-'a'+10:(x)-'A'+10:(x)-'0')
#define bcddigit(x) ((x)>=10?'A'-10+(x):'0'+(x))

#define X9_KEY_ALGORITHM_TDEA			0x54
#define X9_KEY_USAGE_DUKPT_IKEY			0x4231
#define X9_KEY_MODE_OF_USE_DERIVE		0x58
#define X9_KEY_VERSION_NO_VERSION		0x3030
#define X9_KEY_BLOCK_VERSION_ID			0x42
#define X9_BLOCK_ID_TIMESTAMP			0x5453

static void bin2hexstr(unsigned char *bin, int size, char *str, char spacing)
{
	register unsigned char r;

	while (size > 0) {
		r = *bin >> 4;
		*str++ = bcddigit(r);
		r = *bin & 0xF;
		*str++ = bcddigit(r);

		if (spacing && (size > 1))
			*str++ = spacing;
		size--;
		bin++;
	}
	*str = 0;
}

int create_key_block_header(char *key_block_header, int *key_block_header_len,
		   uint16_t length, uint16_t usage, uint16_t algo, uint8_t mode,
							       uint16_t version)
{
	struct tm *utc;
	time_t t;
	int i = 4;
	unsigned char digit;

	if (*key_block_header_len < 32)
		return CKR_BUFFER_TOO_SMALL;

	*key_block_header_len = 32;

	/*
	 * Version ID
	 */
	key_block_header[0] = X9_KEY_BLOCK_VERSION_ID;

	/*
	 * Length
	 */
	if (length > 9999)
		return CKR_BUFFER_TOO_SMALL;

	for (i = 4; i > 0; i--) {
		digit = (length % 10) + 0x30;
		key_block_header[i] = digit;
		length /= 10;
	}

	/*
	 * Key Usage
	 */
	key_block_header[5] = (CK_BYTE) (usage >> 8);
	key_block_header[6] = (CK_BYTE) (usage & 0xFF);

	/*
	 * Algorithm
	 *
	 */
	key_block_header[7] = algo;

	/*
	 * Mode of use
	 */
	key_block_header[8] = mode;

	/*
	 * Key version
	 */
	key_block_header[9] = (CK_BYTE) (version >> 8);
	key_block_header[10] = (CK_BYTE) (version & 0xFF);

	/*
	 * Exportability - always 0x45
	 *
	 */
	key_block_header[11] = 0x45;

	/*
	 * One additional block
	 */
	key_block_header[12] = 0x30;
	key_block_header[13] = 0x31;

	/*
	 * RFU
	 */
	key_block_header[14] = 0x30;
	key_block_header[15] = 0x30;

	/*
	 * UTC Timestamp
	 *
	 */
	key_block_header[16] = (CK_BYTE) (X9_BLOCK_ID_TIMESTAMP >> 8);
	key_block_header[17] = (CK_BYTE) (X9_BLOCK_ID_TIMESTAMP & 0xFF);
	key_block_header[18] = 0x31;
	key_block_header[19] = 0x36;
	time(&t);
	utc = gmtime(&t);
	strftime(key_block_header + 20, 13, "%H%M%d%m%Y", utc);

	return CKR_OK;
}

int wrap_key_rsa(EVP_PKEY *signing_key, EVP_PKEY *encryption_key,
	      uint8_t *key_block_header, int key_block_header_len, uint8_t *key,
			int key_len, uint8_t *wrap_buffer, int *wrap_buffer_len)
{
	unsigned char tmp_wrap_buffer[1312];
	uint8_t signature[256];
	size_t signature_len = sizeof(signature);
	uint8_t crypt_buf[384];
	int crypt_buf_len = sizeof(crypt_buf);
	int padding_len;
	int rv;
	EVP_PKEY_CTX *key_ctx;
	EVP_MD_CTX *md_ctx = NULL;

	memset(tmp_wrap_buffer, 0x00, sizeof(tmp_wrap_buffer));
	memset(signature, 0x00, sizeof(signature));
	memset(crypt_buf, 0x00, sizeof(crypt_buf));

	/*
	 * Make sure the wrap buffer size is sufficient
	 * 32 Bytes Key Block Header/One additional key block
	 * 512/768 Bytes Key Block including alignment (HEX-ASCII encoding)
	 * 512 Bytes RSA-2048 signature (HEX-ASCII encoding)
	 */
	padding_len = 32 - ((key_len + 2) % 32);

	/*
	 * Create the actual key block
	 */
	memcpy(tmp_wrap_buffer, key_block_header, key_block_header_len);
	/*
	 * Key length in bits
	 */
	tmp_wrap_buffer[32] = (key_len * 8) >> 8;
	tmp_wrap_buffer[33] = (key_len * 8) & 0xFF;

	/*
	 * Copy key value
	 */
	memcpy(tmp_wrap_buffer + 34, key, key_len);

	/*
	 * Added necessary random padding
	 */
	rv = RAND_bytes(tmp_wrap_buffer + 34 + key_len, padding_len);

	if (!rv) {
		rv = -1;
		goto out;
	}

	/*
	 * Encrypt the key block header, the optional block
	 * and the actual block (including key length, key value
	 * and padding)
	 */
	key_ctx = EVP_PKEY_CTX_new(encryption_key, NULL);
	EVP_PKEY_encrypt_init(key_ctx);
	EVP_PKEY_CTX_set_rsa_padding(key_ctx, RSA_PKCS1_PADDING);

	rv = EVP_PKEY_encrypt(key_ctx, crypt_buf, (size_t *) &crypt_buf_len,
			       tmp_wrap_buffer, 32 + 2 + key_len + padding_len);

	EVP_PKEY_CTX_free(key_ctx);

	if (!rv) {
		rv = -1;
		goto out;
	}

	/*
	 * Append the cryptogram to the temp buffer
	 */
	memcpy(tmp_wrap_buffer + 32, crypt_buf, crypt_buf_len);

	/*
	 * Create the signature
	 */
	md_ctx = EVP_MD_CTX_create();
	EVP_MD_CTX_init(md_ctx);

	rv = EVP_DigestSignInit(md_ctx,&key_ctx, EVP_sha256(), NULL,
								   signing_key);
	if (!rv) {
		rv = -1;
		goto out;
	}

	rv = EVP_PKEY_CTX_set_rsa_padding(key_ctx, RSA_PKCS1_PADDING);
	if (!rv) {
		rv = -1;
		goto out;
	}

	rv = EVP_DigestSignUpdate(md_ctx, tmp_wrap_buffer, 32 + crypt_buf_len);
	if (!rv) {
		rv = -1;
		goto out;
	}

	rv = EVP_DigestSignFinal(md_ctx, signature, (size_t *) &signature_len);
	if (!rv) {
		rv = -1;
		goto out;
	}

	/*
	 * Copy the block header to the output buffer
	 */
	memcpy(wrap_buffer, tmp_wrap_buffer, 32);

	/*
	 * Encode the binary cryptogram as HEX-ASCII and copy it to the
	 * output buffer
	 */
	bin2hexstr(crypt_buf, crypt_buf_len, (char *)(wrap_buffer + 32), 0);

	/*
	 * Encode the binary signature as HEX-ASCII and copy it to the
	 * output buffer
	 */
	bin2hexstr(signature, signature_len,
			     (char *)(wrap_buffer + 32 + 2 * crypt_buf_len), 0);

	*wrap_buffer_len = 32 + 2 * crypt_buf_len + 2 * signature_len;

	rv = 0;

out:
	if (md_ctx != NULL) {
		EVP_MD_CTX_cleanup(md_ctx);
		EVP_MD_CTX_destroy(md_ctx);
	}

	memset_s(tmp_wrap_buffer, 0x00, sizeof(tmp_wrap_buffer));
	memset_s(signature, 0x00, sizeof(signature));
	memset_s(crypt_buf, 0x00, sizeof(crypt_buf));

	return rv;
}

int create_generic_RSA_wrapping_block(EVP_PKEY *signing_key,
	  EVP_PKEY *encryption_key, uint16_t usage, uint16_t algo, uint8_t mode,
	      uint16_t version, uint8_t *key, int key_len, uint8_t *wrap_buffer,
							   int *wrap_buffer_len)
{
	unsigned char key_block_header[32];
	int key_block_header_len = sizeof(key_block_header);
	int wrapping_key_len;
	int key_block_total_len;
	int rv;

	wrapping_key_len = EVP_PKEY_size(encryption_key);
	key_block_total_len =
		   32 + (2 * wrapping_key_len) + 2 * EVP_PKEY_size(signing_key);

	key_block_header_len = sizeof(key_block_header);
	rv = create_key_block_header((char *)key_block_header,
		  &key_block_header_len, key_block_total_len, usage, algo, mode,
								       version);

	if (rv != CKR_OK)
		return -1;

	rv = wrap_key_rsa(signing_key,
			encryption_key,
			key_block_header, key_block_header_len,
			key, key_len,
			wrap_buffer, wrap_buffer_len);

	if (rv != 0)
		return -1;

	return 0;
}

X509 *load_cert(const char *fn)
{
	FILE *fp_x509 = NULL;
	X509 *x509_cert = NULL;

	fp_x509 = fopen(fn, "r");
	if (!fp_x509)
		return NULL;

	x509_cert = PEM_read_X509(fp_x509, NULL, NULL, NULL);
	if (!x509_cert) {
		fclose(fp_x509);
		return NULL;
	}

	fclose(fp_x509);

	return x509_cert;
}

EVP_PKEY *load_private_key(const char *fn)
{
	FILE *fp = NULL;
	EVP_PKEY *key = NULL;

	fp = fopen(fn, "r");
	if (!fp)
		return NULL;

	key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	if (!key) {
		fclose(fp);
		return NULL;
	}

	fclose(fp);

	return key;
}

static void derive_initial_key(const unsigned char base_derivation_key[16],
				      const unsigned char key_serial_number[10],
						  unsigned char initial_key[16])
{
	EVP_CIPHER_CTX *ctx = NULL;
	unsigned char bdk[16], ksn[8];
	int outlen = 0, tmplen = 0, i = 0;

	memcpy(bdk, base_derivation_key, sizeof(bdk));
	memcpy(ksn, key_serial_number, sizeof(ksn));

	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_des_ede(), NULL, bdk, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_EncryptUpdate(ctx, &initial_key[outlen], &outlen, ksn, 8);
	EVP_EncryptFinal_ex(ctx, &initial_key[outlen], &tmplen);
	EVP_CIPHER_CTX_free(ctx);
	outlen += tmplen;

	for (i = 0; i < 4; i++)
		bdk[i] ^= 0xC0;

	for (i = 8; i < 12; i++)
		bdk[i] ^= 0xC0;

	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_des_ede(), NULL, bdk, NULL);
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	EVP_EncryptUpdate(ctx, &initial_key[outlen], &outlen, ksn, 8);
	EVP_EncryptFinal_ex(ctx, &initial_key[outlen], &tmplen);
	EVP_CIPHER_CTX_free(ctx);
	outlen += tmplen;
}

static EVP_PKEY *get_terminal_key_encryption_key(CK_SESSION_HANDLE hSession)
{
	CK_OBJECT_CLASS certificateClass = CKO_CERTIFICATE;
	CK_OBJECT_HANDLE cert_handle = CK_INVALID_HANDLE;
	CK_CERTIFICATE_TYPE cerType = CKC_X_509;
	uint16_t id = FEPKCS11_TERM_KEK_ID;
	unsigned char x509_der[2048];
	const unsigned char *p_x509_der = (const unsigned char *)x509_der;
	CK_ULONG ulObjectCount;
	CK_RV rv = CKR_OK;
	CK_ATTRIBUTE cert_search_template[] = {
		{ CKA_CLASS, &certificateClass, sizeof(certificateClass) },
		{ CKA_CERTIFICATE_TYPE, &cerType, sizeof(cerType) },
		{ CKA_ID, &id, sizeof(id) }
	};
	CK_ATTRIBUTE cert_value[] = {
		{ CKA_VALUE, x509_der, sizeof(x509_der) }
	};
	EVP_PKEY *kek = NULL;
	X509 *kek_cert = NULL;

	rv = C_FindObjectsInit(hSession, cert_search_template,
					      ARRAY_SIZE(cert_search_template));
	assert(rv == CKR_OK);

	rv = C_FindObjects(hSession, &cert_handle, 1, &ulObjectCount);
	assert(rv == CKR_OK);
	assert(ulObjectCount == 1);
	assert(cert_handle != CK_INVALID_HANDLE);

	rv = C_FindObjectsFinal(hSession);
	assert(rv == CKR_OK);

	rv = C_GetAttributeValue(hSession, cert_handle, cert_value,
							ARRAY_SIZE(cert_value));
	assert(rv == CKR_OK);

	kek_cert = d2i_X509(NULL, &p_x509_der, cert_value[0].ulValueLen);
	assert(kek_cert);

	kek = X509_get_pubkey(kek_cert);
	assert(kek);

	X509_free(kek_cert);

	return kek;
}

static void get_tr31_keyblock_for_dukpt_initial_key(CK_SESSION_HANDLE hSession,
				    const unsigned char base_derivation_key[16],
	    const unsigned char key_serial_number[10], char tr31_keyblock[2048])
{
	EVP_PKEY *terminal_key_encryption_key = NULL;
	EVP_PKEY *kid_signing_key = NULL;
	unsigned char initial_key[16];
	int rc = 0, len = 2048;

	terminal_key_encryption_key = get_terminal_key_encryption_key(hSession);
	assert(terminal_key_encryption_key != NULL);

	kid_signing_key = load_private_key("/etc/ssl/private/kid-key.pem");
	assert(kid_signing_key != NULL);

	derive_initial_key(base_derivation_key, key_serial_number, initial_key);

	rc = create_generic_RSA_wrapping_block(kid_signing_key,
			   terminal_key_encryption_key, X9_KEY_USAGE_DUKPT_IKEY,
			       X9_KEY_ALGORITHM_TDEA, X9_KEY_MODE_OF_USE_DERIVE,
		    X9_KEY_VERSION_NO_VERSION, initial_key, sizeof(initial_key),
						(uint8_t *)tr31_keyblock, &len);
	assert(rc == 0);
	tr31_keyblock[len] = '\0';

	EVP_PKEY_free(terminal_key_encryption_key);
	EVP_PKEY_free(kid_signing_key);
}

static void unwrap_dukpt_initial_key(CK_SESSION_HANDLE hSession,
	  char *tr31_keyblock, unsigned char key_serial_number[10], char *label,
								    uint16_t id)
{
	CK_OBJECT_CLASS dukptClass = CKO_DUKPT_IKEY;
	CK_KEY_TYPE dukptKeyType = CKK_DES2;
	CK_BBOOL ckTrue = CK_TRUE;
	CK_BBOOL ckFalse = CK_FALSE;
	CK_OBJECT_CLASS certificateClass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE cerType = CKC_X_509;
	CK_OBJECT_HANDLE hCertKSK = CK_INVALID_HANDLE, hIK = CK_INVALID_HANDLE;
	CK_MECHANISM mech_tr31 = {
		CKM_WRAP_TR31_KEY_BLOCK_BINDING, NULL_PTR, 0
	};
	CK_ATTRIBUTE attrs_dukpt_key[] = {
		{ CKA_CLASS, &dukptClass, sizeof(dukptClass) },
		{ CKA_KEY_TYPE, &dukptKeyType, sizeof(dukptKeyType) },
		{ CKA_LABEL, label, strlen(label) },
		{ CKA_ID, &id, sizeof(id) },
		{ CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
		{ CKA_DERIVE, &ckTrue, sizeof(ckTrue) },
		{ CKA_DUKPT_KEY_SERIAL_NUMBER, key_serial_number, 10 },
	};
	CK_ATTRIBUTE kid_cert_template[] = {
		{ CKA_VALUE, NULL, 0},
		{ CKA_CLASS, &certificateClass, sizeof(certificateClass) },
		{ CKA_CERTIFICATE_TYPE, &cerType, sizeof(cerType) },
		{ CKA_TOKEN, &ckFalse, sizeof(ckFalse) }
	};
	CK_RV rv = CKR_OK;
	X509 *kid_cert = NULL;
	unsigned char kid_cert_der[2048], *p_kid_cert_der = kid_cert_der;
	int kid_cert_der_len = 0;

	kid_cert = load_cert("/etc/ssl/certs/kid-cert.pem");
	assert(kid_cert != NULL);

	kid_cert_der_len = i2d_X509(kid_cert, &p_kid_cert_der);
	assert(kid_cert_der_len > 0);

	X509_free(kid_cert);

	kid_cert_template[0].pValue = (CK_VOID_PTR)kid_cert_der;
	kid_cert_template[0].ulValueLen = (CK_ULONG)kid_cert_der_len;

	rv = C_CreateObject(hSession, kid_cert_template,
				      ARRAY_SIZE(kid_cert_template), &hCertKSK);
	assert(rv == CKR_OK);


	rv = C_UnwrapKey(hSession, &mech_tr31, hCertKSK,
		    (CK_BYTE_PTR)tr31_keyblock, (CK_ULONG)strlen(tr31_keyblock),
			    attrs_dukpt_key, ARRAY_SIZE(attrs_dukpt_key), &hIK);
	assert(rv == CKR_OK);

}

void inject_dukpt_initial_key(CK_SESSION_HANDLE hSession,
					  unsigned char base_derivation_key[16],
		  unsigned char key_serial_number[10], char *label, uint16_t id)
{
	char tr31_keyblock[2048];

	get_tr31_keyblock_for_dukpt_initial_key(hSession, base_derivation_key,
					      key_serial_number, tr31_keyblock);

	unwrap_dukpt_initial_key(hSession, tr31_keyblock, key_serial_number,
								     label, id);
}

void crypto_token_login(CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV rv = CKR_OK;

	rv = C_Initialize(NULL_PTR);
	assert(rv == CKR_OK);

	rv = C_OpenSession(FEPKCS11_APP0_TOKEN_SLOT_ID,
		    CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, phSession);
	assert(rv == CKR_OK);

	rv = C_Login(*phSession, CKU_USER, NULL_PTR, 0);
	assert(rv == CKR_OK);
}

void crypto_token_logout(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;

	rv = C_Logout(hSession);
	assert(rv == CKR_OK);

	rv = C_CloseSession(hSession);
	assert(rv == CKR_OK);

	rv = C_Finalize(NULL_PTR);
	assert(rv == CKR_OK);
}

int is_dukpt_initial_key_present(CK_SESSION_HANDLE hSession, char *label,
								    uint16_t id)
{
	CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
	CK_OBJECT_CLASS dukptClass = CKO_DUKPT_IKEY;
	CK_KEY_TYPE dukptKeyType = CKK_DES2;
	CK_ATTRIBUTE attrs_dukpt_key[] = {
		{ CKA_CLASS, &dukptClass, sizeof(dukptClass) },
		{ CKA_KEY_TYPE, &dukptKeyType, sizeof(dukptKeyType) },
		{ CKA_LABEL, label, strlen(label) },
		{ CKA_ID, &id, sizeof(id) }
	};
	CK_ULONG ulObjectCount = 0;
	CK_RV rv = CKR_OK;

	rv = C_FindObjectsInit(hSession, attrs_dukpt_key,
						   ARRAY_SIZE(attrs_dukpt_key));
	assert(rv == CKR_OK);

	rv = C_FindObjects(hSession, &hKey, 1, &ulObjectCount);
	assert(rv == CKR_OK);

	rv = C_FindObjectsFinal(hSession);
	assert(rv == CKR_OK);

	if (ulObjectCount) {
		char yesno[16];

		printf("Key (label '%s', id 0x%02hX) already present.\n",
								     label, id);
		printf("Destroy and re-inject? [y/N]? ");
		fgets(yesno, sizeof(yesno), stdin);

		if (yesno[0] == 'Y' || yesno[0] == 'y') {
			rv = C_DestroyObject(hSession, hKey);
			assert(rv == CKR_OK);
			ulObjectCount = 0;
		}
	}

	return (int)ulObjectCount;
}

int main(void)
{
	CK_SESSION_HANDLE hSession = CK_INVALID_HANDLE;
	unsigned char base_derivation_key[16] = {
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
	};
	unsigned char key_serial_number[10] = {
		0xFF, 0xFF, 0x98, 0x76, 0x54, 0x32, 0x10, 0xE0, 0x00, 0x00
	};
	char label[] = "DUKPT_IKEY";
	uint16_t id = 0xCC01;

	crypto_token_login(&hSession);

	if (!is_dukpt_initial_key_present(hSession, label, id))
		inject_dukpt_initial_key(hSession, base_derivation_key,
						  key_serial_number, label, id);

	crypto_token_logout(hSession);

	return EXIT_SUCCESS;
}
