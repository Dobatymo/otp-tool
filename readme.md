# otp-tool

## Features

- Generate time-based one-time passwords (also called 2FA or MFA tokens) according to [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)
  - include additional information like name, issuer and remaining time
  - print and exit or show a live refreshing table view
- Fully offline, no internet access whatsoever
- Secrets are stored locally, fully encrypted using `PyNaCl` (Argon2id as KDF, XSalsa20 stream cipher and Poly1305 MAC for authentication)
- Allows to export stored secrets as `otpauth` URIs (which should be supported by most other authenticator apps)
- Cloud sync can be done by storing the secrets file in a cloud drive of your choice
- Read QR codes from file or find them on the screen (with multi monitor support)

## Possible improvements
- Improve export in different formats
- The CLI command interface is still a bit tedious to use

## Requirements

Python 3.8+.

## Install

- without QR feature: `pip install git+https://github.com/Dobatymo/otp-tool`
- with QR featrue: `pip install "otp[qr] @ git+https://github.com/Dobatymo/otp-tool"`

## Demo

![](https://github.com/Dobatymo/otp-tool/blob/master/docs/otp.gif)
