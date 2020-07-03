# libmutotp

libMUTOTP is a C library designed to bring easy Two-Factor Authentication to
MU*s and other text mode applications.

The library can generate TOTP QR codes in ANSI graphics, which you can then display
on most ANSI-compatible virtual terminals or MU* clients. The QR codes are smaller
than 80x40 characters.

Your users can use any TFA app like "Authenticator", to scan ANSI QR codes
and generate one-time passwords with. OTPs can be between 1 and 8 digits long,
inclusive (6 is the most popular length).

![Demo code (don't use for anything)](https://i.imgur.com/RO9dWYC.png)

# Usage:
## Making a new secret and QR code
```
char secret[33] = {0};
//Create a base32 encoded secret in an ascii string
generate_random_secret(secret, 33);
printf("Secret: %s\n", secret);

//Create an ANSI QR code graphic. The pointer on the line below owns its new heap memory.
char* qrcodeansi = create_totp_qrcode("Test", "Meow", secret);

printf("--------------------------------------------------------------------------------\n");
printf("%s\n", qrcodeansi);

//Free the memory holding the ANSI QR code graphic
free(qrcodeansi);
```

## Checking the validity of an entered OTP
```
char secret[33] = {0};
char buf[512] = {0};

//In actual use, you would store the secret with the user's account instead of
//prompting for it, then retrieve it later when he logs in to validate his
//OTPs with.

printf("Enter secret to compute current TOTP:");
scanf("%s", buf);

//Decode the secret from base32 ASCII to its raw data
size_t secretlen = base32decode(buf, strnlen(buf, 512), secret, 33);

//Compute current TOTP using the entered secret and current time.
//The user's authenticator app will do the same calculation for them,
//and if both their app and this program agree (are time-synced and share
//the same secret), the user's OTP will match the one below.
time_t now = time(0);
int otp = compute_totp(secret, secretlen, now, 30, 6);
printf("Current otp code: %06d\n", otp);

```

# Licenses
libmutotp is licensed under the LGPL 2.1. Its SHA1 code was written by Steve Reid and is in public domain.
