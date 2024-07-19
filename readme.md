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
- Add importing (aligned to exports, and possibly from other authenticator apps)
- The CLI command interface is still a bit tedious to use
- Confirm delete or "add using qr code" operations

## Requirements

Python 3.8+.

## Install

- without QR feature: `pip install git+https://github.com/Dobatymo/otp-tool`
- with QR featrue: `pip install "otp[qr] @ git+https://github.com/Dobatymo/otp-tool"`

## CLI help

```
usage: otp.py [-h] [--verbose] [--path PATH] [--secret ASCII-STRING]
              {show,export,change-password,remove,screenshot-qr,add-qr,add-uri,add-totp,add-hotp} ...

positional arguments:
  {show,export,change-password,remove,screenshot-qr,add-qr,add-uri,add-totp,add-hotp}
    show                Show OTP tokens
    export              Export OTP secrets (not tokens) to file or print to screen
    change-password     Change password secrets database file
    remove              Remove OTP from database
    screenshot-qr       Add OTP to database by takeing a screenshot and scan for QR codes.
    add-qr              Add OTP to database by reading a QR code from a image file.
    add-uri             Add OTP to database by otpauth URI
    add-totp            Add Time-based one-time password (TOTP)
    add-hotp            Add HMAC-based one-time password (HOTP)

optional arguments:
  -h, --help            show this help message and exit
  --verbose             Print debug information (default: False)
  --path PATH           Path to the file where the secrets are stored. (default:
                        C:\Users\<username>\AppData\Local\Dobatymo\otp-tool\otp.json)
  --secret ASCII-STRING
                        Password to encrypt OTP file. Needs to be ASCII. If not specified it will show a input prompt.
                        (default: None)
```

## Demo (CLI interface has since been changed)

![](https://github.com/Dobatymo/otp-tool/blob/master/docs/otp.gif)
