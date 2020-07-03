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
#include <assert.h>
//#include <check.h>
#include <string.h>
#include "base32codec.h"

//TODO: Find another unit testing framework. libcheck leaks memory!

//START_TEST(check_encode)
int check_encode()
{
	static const char* test_strings[] = {
		"", "f", "fo", "foo", "foob",
		"fooba", "foobar","The quick red fox jumped over the lazy brown dogs."
	};
	static const char* expected_strings[] = {
		"", "MY======", "MZXQ====", "MZXW6===",
		"MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======",
		"KRUGKIDROVUWG2ZAOJSWIIDGN54CA2TVNVYGKZBAN53GK4RAORUGKIDMMF5HSIDCOJXXO3RAMRXWO4ZO"
	};
	size_t test_strings_len = sizeof(test_strings)/sizeof(const char*);
	size_t idx = 0;
	for(; idx < test_strings_len; ++idx)
	{
		size_t outlen = 256;
		char* out = malloc(outlen);
		memset(out, 0, outlen);
		const char* teststring = test_strings[idx];
		int retval = base32encode(teststring, strlen(teststring), out, outlen);
		//ck_assert(retval >= 0);
		//ck_assert(0 == strcmp(out, expected_strings[idx]));
		if(retval < 0 || 0 != strcmp(out, expected_strings[idx]))
		{
			free(out);
			return -1;
		}
		free(out);
	}
	return 0;
}

//START_TEST(check_decode)
int check_decode()
{
	static const char* test_strings[] =
	{
		"", "MY======", "MZXQ====", "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======",
		"KRUGKIDROVUWG2ZAOJSWIIDGN54CA2TVNVYGKZBAN53GK4RAORUGKIDMMF5HSIDCOJXXO3RAMRXWO4ZO"
	};

	static const char* expected_strings[] = {
		"", "f", "fo", "foo", "foob", "fooba", "foobar",
		"The quick red fox jumped over the lazy brown dogs."
	};
	size_t test_strings_len = sizeof(test_strings)/sizeof(const char*);
	size_t idx = 0;
	for(; idx < test_strings_len; ++idx)
	{
		size_t outlen = 256;
		char* out = malloc(outlen);
		memset(out, 0, outlen);
		const char* teststring = test_strings[idx];
		int retval = base32decode(teststring, strlen(teststring), out, outlen);
		//ck_assert(retval >= 0);
		//ck_assert(0 == strcmp(out, expected_strings[idx]));
		if(retval < 0 || 0 != strcmp(out, expected_strings[idx]))
		{
			free(out);
			return -1;
		}
		free(out);
	}
	return 0;
}
/*
Suite* b32_test_suite(void)
{
	Suite* s = suite_create("base32_codec");
	TCase* testcases = tcase_create("Core");

	tcase_add_test(testcases, check_encode);
	tcase_add_test(testcases, check_decode);

	suite_add_tcase(s, testcases);

	return s;
}
*/
int main(void)
{
	/*
	Suite* s = b32_test_suite();
	SRunner* sr = srunner_create(s);

	srunner_run_all(sr, CK_VERBOSE);
	size_t tests_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return tests_failed ? EXIT_FAILURE : EXIT_SUCCESS;
	*/
	printf("Decoder test %s.\n", check_decode() < 0 ? "failed" : "passed");
	printf("Encoder test %s.\n", check_encode() < 0 ? "failed" : "passed");

	return 0;
}
