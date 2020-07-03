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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "totp.h"
#include "base32codec.h"

void demo_ansi_qrcode()
{
	char secret[33] = {0};
	//Create a base32 encoded secret in an ascii string
	generate_random_secret(secret, 33);
	printf("Secret: %s\n", secret);

	//Create an ANSI QR code graphic. qrcodeansi owns the new heap memory.
	char* qrcodeansi = create_totp_qrcode("Test", "Meow", secret);

	printf("--------------------------------------------------------------------------------\n");
	printf("%s\n", qrcodeansi);

	//Free the memory holding the ANSI QR code graphic
	free(qrcodeansi);
}

void demo_totp_calculation()
{
	char secret[33] = {0};
	char buf[512] = {0};

	printf("Enter secret to compute current TOTP:");
	scanf("%s", buf);

	//Decode the secret from base32 ASCII to its raw data
	size_t secretlen = base32decode(buf, strnlen(buf, 512),
					secret, 41);

	//Compute current TOTP using the entered secret and current time.  In
	//actual use you would store the secret after it is generated, then
	//later use it to compute the TOTP each time the user makes an auth
	//attempt. See RFC 6238 for more information.

	time_t now = time(0);
	int otp = compute_totp(secret, secretlen, now, 30, 6);
	printf("Current otp code: %06d\n", otp);
}

int main(void)
{
	demo_ansi_qrcode();
	demo_totp_calculation();
	return 0;
}
