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

#ifndef TOTP_H_
#define TOTP_H_
#include <stdint.h>
#include <stddef.h>
#include <time.h>

struct totpuri
{
/* A Time-based One Time Password Uniform Resource Identifier
 */
	char label[17];
	char secret[33];
	char issuer[17];
	char uristr[107];
};

void totpuri_init(struct totpuri* uri, const char* label, const char* issuer,
		const char* secret);
/* totpuri_init fills out a totpuri structure using its null terminated string
 * arguments.

 * label - a null terminated string at most 16 + 1 bytes long
 * secret - a null terminated string
 */


char* create_totp_qrcode(const char* label, const char* issuer, const char* secret);
/* create_totp_qrcode: generates an ANSI v4 QR code with a TOTP secret
 * label - null-terminated string. Descriptive label up to 16 + 1 characters long
 * issuer - null-terminated string. Name of issuer up to 16 + 1 characters long
*/


int32_t compute_totp(const char* secret, size_t secretlen,
		time_t timestamp, size_t timestep, size_t digits);
/* compute_totp: calculates totp based on timestamp and secret
 *
 * secret - null-terminated string containing an ENCODED base32 secret
 * timestamp - typically the UNIX UTC timestamp for current time, i.e: time(0)
 * timestep - how many seconds OTP should remain valid; almost always 30
 * digits - how many digits (1 - 8) should be in the OTP. 6 is common
 */
int generate_random_secret(char* out, size_t outlen, int32_t (*rgen)(uint8_t*, size_t));
/* generate_random_secret: generates a random secret encoded in base32.
 *
 * out - pointer to output buffer
 * outlen - size of buffer in bytes. Must be at least 33 bytes long.
 * rgen - a function that fills the buffer pointed to by the first argument, of length equal to the 2nd argument, with random bytes
 *	  and which returns -1 on failure and anything else on success
 */

 void hmacsha1(char* output, const char* key,
	size_t key_len, const char* message,
	size_t message_len);
/* hmacsha1: hashed message authentication code using SHA1
 */

#endif
