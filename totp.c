/*
 * libmutotp - a library for using and making TOTP QR codes
 * Copyright (C) 2020 kmeow
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as publ-
 * ished by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
*/

#include "totp.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sha1.h"
#include "base32codec.h"
#include "qrcode/qrcode.h"

void totpuri_init(struct totpuri* uri, const char* label, const char* issuer,
		const char* secret)
{
	memset(uri, 0, sizeof(struct totpuri));

	//The uri format string text alone takes up 33 characters
	//The maximum length of the URI is 106 characters in a version 5 QR code

	snprintf(uri->label, sizeof(uri->label), label);
	snprintf(uri->secret, sizeof(uri->secret), secret);
	snprintf(uri->issuer, sizeof(uri->issuer), issuer);
	snprintf(uri->uristr, sizeof(uri->uristr), "otpauth://totp/%s?secret=%s&issuer=%s",
		uri->label, uri->secret, uri->issuer);
}

char* create_totp_qrcode(const char* label, const char* issuer, const char* secret)
{
	QRCode qrcode;
	uint8_t qrcodever = 4;
	size_t qrcodelen = qrcode_getBufferSize(qrcodever);
	uint8_t* qrcodedata = (char*) malloc(qrcodelen);

	struct totpuri uri;
	totpuri_init(&uri, label, issuer, secret);
	qrcode_initText(&qrcode, qrcodedata, qrcodever, ECC_LOW, uri.uristr);

	uint8_t y = 0, x = 0;
	uint32_t i = 0;

	static const char* rev = "\x1B[07m";
	static const char* def = "\x1B[0m";

	size_t qrcodeansilen = (7 * qrcode.size * qrcode.size) + 1;
	uint8_t* qrcodeansi = (char*) malloc(qrcodeansilen);
	memset(qrcodeansi, 0 , qrcodeansilen);
	size_t idx = 0;
	uint8_t lastansi = 0;
	for(y = 0; y < qrcode.size; ++y)
	{
		for(x = 0; x < qrcode.size; ++x)
		{
			if(qrcode_getModule(&qrcode, x, y))
			{
				idx += snprintf(&qrcodeansi[idx], qrcodeansilen - idx, "%s  ",
						1 == lastansi ? "" : rev);
				lastansi = 1;
			}
			else
			{
				idx += snprintf(&qrcodeansi[idx], qrcodeansilen - idx, "%s  ",
						0 == lastansi ? "" : def);
				lastansi = 0;
			}
		}
		idx += snprintf(&qrcodeansi[idx], qrcodeansilen - idx, "\n");
	}
	idx += snprintf(&qrcodeansi[idx], qrcodeansilen - idx, "%s", def);

	free(qrcodedata);
	return qrcodeansi;
}

static time_t flip_ts_endianness(time_t timestamp)
{
	size_t idx = 0, len = sizeof(time_t);
	time_t output = 0;
	char* pOutput = (char*) &output;
	for(; idx < len; ++idx)
	{
		pOutput[idx] = (timestamp >> ((len - idx - 1) << 3)) & 0xff;
	}
	return output;
}

int generate_random_secret(char* out, size_t outlen, int32_t (*rgen)(uint8_t*, size_t))
{
	//Generate a 160-bit random value encoded in a 32 character long base32
	//encoded ASCII string
	if(outlen < 33)
	{
		return -1;
	}

	uint8_t secret[20] = {0};

	if(rgen(secret, 20) < 0)
	{
		return -1;
	}

	return base32encode(secret, 20, out, outlen);
}

int32_t compute_totp(const char* secret, size_t secretlen,
		time_t timestamp, size_t timestep, size_t digits)
{
	static const int32_t ddivisor[] =
	{
		1, 10, 100, 1000, 10000, 100000, 1000000,
		10000000, 100000000
	};

	if(digits >= sizeof(ddivisor)/sizeof(uint32_t))
	{
		return -1;
	}

	uint8_t result[20] = {0};
	uint8_t hexstr[41] = {0};
	time_t counter = timestamp / timestep;
	//TODO: This only needs to be done on little endian machines
	time_t counterbe = flip_ts_endianness(counter);

	hmacsha1(result, secret, secretlen,
		(char*) &counterbe, sizeof(time_t));

	int32_t offset = result[19] & 0x0f;
	int32_t truncated = ((result[offset] & 0x7f) << 24) |
		((result[offset + 1] & 0xff) << 16) |
		((result[offset + 2] & 0xff) << 8) |
		(result[offset + 3] & 0xff);

	return truncated % ddivisor[digits];
}

#ifndef min
#define min(a, b) (a < b ? a : b)
#endif

void hmacsha1(char* output, const char* key, size_t key_len, const char* message, size_t message_len)
{
	char okeypad[64] = {0};
	char ikeypad[64] = {0};
	char keybuf[128] = {0};
	memcpy(keybuf, key, min(128, key_len));

	if(strnlen(keybuf, 128) > 64)
	{
		//Hash a key which is longer than the SHA1 block size (64 bytes)
		char keyout[128] = {0};
		SHA1(keyout, keybuf, strnlen(keybuf, 128));
		memset(keybuf, 0, 128);
		memcpy(keybuf, keyout, 128);
	}

	size_t idx = 0;
	for(; idx < 16; ++idx)
	{
		((unsigned int*) okeypad)[idx] = ((unsigned int*) keybuf)[idx] ^ 0x5c5c5c5c;
		((unsigned int*) ikeypad)[idx] = ((unsigned int*) keybuf)[idx] ^ 0x36363636;
	}

	//bc = ikeypad + message
	//a = okeypad + Hash(bc)
	//HMAC = Hash(a)

	size_t bc_len = 64 + message_len;
	size_t a_len = 84; //64 + 20
	char* bc = malloc(bc_len + 1);
	char* a = malloc(a_len + 1);

	memcpy(bc, ikeypad, 64);
	memcpy(&bc[64], message, message_len);

	memcpy(a, okeypad, 64);
	SHA1(&a[64], bc, bc_len);
	SHA1(output, a, a_len);

	free(a);
	free(bc);
}
