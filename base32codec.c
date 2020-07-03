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

#include "base32codec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int32_t base32decode(const char* input, size_t input_len, char* output, size_t output_len)
{
	//TODO: This works for little endian only!
	memset(output, 0, sizeof(output_len));
	static const char valtable[] =
		{
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,  26,  27,  28,  29,  30,  31,
                        -128,-128,-128,-128,-128,  -1,-128,-128,
                        -128,   0,   1,   2,   3,   4,   5,   6,
                           7,   8,   9,  10,  11,  12,  13,  14,
                          15,  16,  17,  18,  19,  20,  21,  22,
                          23,  24,  25,-128,-128,-128,-128,-128,
                        -128,   0,   1,   2,   3,   4,   5,   6,
                           7,   8,   9,  10,  11,  12,  13,  14,
                          15,  16,  17,  18,  19,  20,  21,  22,
                          23,  24,  25,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128,
                        -128,-128,-128,-128,-128,-128,-128,-128
		};

	int32_t idx = 0, out_idx = 0;

	int32_t uncopiedbits = 0;
	uint32_t data = 0;
	uint32_t datactr = 0;

	for(; idx < input_len; ++idx)
	{
		char value = valtable[input[idx]];
		if(value & 0x80)
		{
			if(value & 0xFF)
			{
				//Padding
				continue;
			}
			else
			{
				//Invalid character
				return -1;
			}
		}

		data |= value;

		uncopiedbits += 5;
		if(uncopiedbits >= 24)
		{
			uint32_t remainderbits = 32 - uncopiedbits;
			uint32_t remainder = data & 0xff;
			data <<= remainderbits;
			if(out_idx + 2 >= output_len)
			{
				return -1;
			}
			output[out_idx] = ((unsigned char*) &data)[3];
			output[out_idx + 1] = ((unsigned char*) &data)[2];
			output[out_idx + 2] = ((unsigned char*) &data)[1];
			data = remainder;
			out_idx += 3;
			uncopiedbits -= 24;
		}
		data <<= 5;
	}

	if(uncopiedbits)
	{
		uint32_t remainderbits = 32 - (uncopiedbits + 5);

		data <<= remainderbits;
		size_t idx = 0;
		size_t uncopiedbytes = uncopiedbits >> 3;
		if((out_idx + (uncopiedbytes - idx)) >= output_len)
		{
			return -1;
		}
		for(; idx < uncopiedbytes; ++idx)
		{
			output[out_idx + idx] = ((unsigned char*) &data)[3 - idx];
		}
		out_idx += uncopiedbytes;
	}
	return out_idx;
}

static inline int32_t nextmultipleof8(int32_t dividend)
{
	int32_t r = dividend - (dividend & ~7); // ((dividend >> 3) << 3);
        return (dividend - r) + 8;
}

static inline int32_t nextmultipleof5(int32_t dividend)
{
	return (dividend - (dividend % 5)) + 5;
}

int32_t base32encode(const char* input, size_t input_len, char* output, size_t output_len)
{
	//TODO: This works for little endian only!
	static const char* valtable = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	size_t idx = 0, out_idx = 0;
	int32_t data = 0, bread = 0;
	for(; idx < input_len; ++idx)
	{
		data |= input[idx] & 0x0FF;
		bread += 8;

		if(bread >= 25)
		{
			uint32_t remainder = (data & 0x7f);
			data <<= 32 - bread;
			if((out_idx + 5) >= output_len)
			{
				return -1;
			}
			output[out_idx] = valtable[(data & 0xF8000000) >> 27];
			output[out_idx + 1] = valtable[(data & 0x7c00000) >> 22];
			output[out_idx + 2] = valtable[(data & 0x3e0000) >> 17];
			output[out_idx + 3] = valtable[(data & 0x1f000) >> 12];
			output[out_idx + 4] = valtable[(data & 0xf80) >> 7];
			out_idx += 5;
			data = remainder;
			bread -= 25;
		}

		data <<= 8;
	}

	if(bread)
	{
		//If there are still bits left to encode
		uint32_t remainderbits = 32 - (bread + 8);
		size_t idx = 0;

		size_t times = bread % 5 ? (nextmultipleof5(bread) / 5) : bread/5;

		data <<= remainderbits;

		if((out_idx + times) >= output_len)
		{
			return -1;
		}

		for(; idx < times; ++idx)
		{
			uint32_t bitshift = 5 * idx;
			output[out_idx + idx] = valtable[(data & (0xF8000000 >> bitshift)) >> (27 - bitshift)];
			bread -= 5;
		}
		out_idx += idx;

		//out_idx is set to the next empty output buffer position,
		//so we subtract 1 from it in the next couple of calculations
		//to use it as the length of the data already in the buffer
		uint32_t nextmultiple = nextmultipleof8(out_idx - 1);

		if(nextmultiple != ((out_idx - 1) + 8))
		{
			if(nextmultiple + 1 >= output_len)
			{
				return -1;
			}
			for(;out_idx < output_len && out_idx < nextmultiple; ++out_idx)
			{
				//Pad output to next multiple of 8
				output[out_idx] = '=';
			}
		}

		output[out_idx] = 0;
	}

	return out_idx;
}
