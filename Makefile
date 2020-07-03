# libmutotp - a library for using and making TOTP QR codes
# Copyright (C) 2020 kmeow

# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as publ-
# ished by the Free Software Foundation; either version 2.1 of the
# License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 USA

CC = gcc

totp_demo: totp_demo.o sha1.o base32codec.o totp.o qrcode/qrcode.o

totp_demo.o: totp_demo.c totp.o

test: base32test

base32test: base32codec.o base32test.o

base32test.o: base32test.c

base32codec.o: base32codec.c

qrcode/qrcode.o: qrcode/qrcode.c

totp.o: totp.c sha1.o qrcode/qrcode.o

sha1.o: sha1.c

clean:
	rm -f *.o totp_demo base32test
