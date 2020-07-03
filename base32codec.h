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

#ifndef BASE32CODEC_H_
#define BASE32CODEC_H_

#include <stdint.h>
#include <stddef.h>

//Returns -1 on error, otherwise returns amount of bytes in output
int32_t base32decode(const char* input, size_t input_len,
		char* output, size_t output_len);

int32_t base32encode(const char* input, size_t input_len,
		char* output, size_t output_len);

#endif
