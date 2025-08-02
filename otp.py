"""OTP CLI"""

import base64
import binascii
import csv
import hashlib
import json
import logging
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser, ArgumentTypeError, Namespace
from datetime import datetime
from getpass import getpass
from pathlib import Path
from time import sleep
from typing import Any, Callable, Dict, List, Optional, Tuple, TypedDict, TypeVar

import pyotp
from genutility.atomic import write_file
from genutility.file import StdoutFile
from nacl import pwhash
from nacl.exceptions import CryptoError
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from platformdirs import user_data_dir
from rich.console import Console
from rich.live import Live
from rich.table import Table
from typing_extensions import Self

__version__ = "0.0.1"

T = TypeVar("T")

APPNAME = "otp-tool"
APPAUTHOR = "Dobatymo"

DEFAULT_OPSLIMIT = pwhash.argon2i.OPSLIMIT_SENSITIVE
DEFAULT_MEMLIMIT = pwhash.argon2i.MEMLIMIT_SENSITIVE


class KdfConfig(TypedDict):
    salt: bytes
    opslimit: int
    memlimit: int


class OtpsStorage(TypedDict):
    kdf_config: KdfConfig
    otps_encrypted: bytes


def hex_to_base32(hex_str: str) -> str:
    bytes_data = binascii.unhexlify(hex_str)
    base32_str = base64.b32encode(bytes_data)
    return base32_str.decode("ascii")


class BinaryEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode("ascii")
        return super().default(obj)


class BinaryDecoder(json.JSONDecoder):
    def __init__(self):
        super().__init__(object_hook=self.object_hook)

    def object_hook(self, obj):
        for key, value in obj.items():
            if isinstance(value, str):
                obj[key] = base64.b64decode(value.encode("ascii"))
        return obj


class OTP:
    def __init__(self, path: Path, kdf_config: KdfConfig, key: bytes, otps: List[pyotp.OTP]) -> None:
        self.path = path

        self.kdf_config = kdf_config
        self.key: Optional[bytes] = key
        self.otps = otps

    @classmethod
    def get_new_key(
        cls, secret: str, opslimit: int = DEFAULT_OPSLIMIT, memlimit: int = DEFAULT_MEMLIMIT
    ) -> Tuple[KdfConfig, bytes]:
        secretb = secret.encode("ascii")
        kdf_config: KdfConfig = {
            "salt": nacl_random(pwhash.argon2i.SALTBYTES),
            "opslimit": opslimit,
            "memlimit": memlimit,
        }
        key = pwhash.argon2i.kdf(SecretBox.KEY_SIZE, secretb, **kdf_config)
        return kdf_config, key

    @classmethod
    def new(cls, path: Path, secret: str, opslimit: int = DEFAULT_OPSLIMIT, memlimit: int = DEFAULT_MEMLIMIT) -> Self:
        kdf_config, key = cls.get_new_key(secret, opslimit, memlimit)
        otps: List[pyotp.OTP] = []
        return cls(path, kdf_config, key, otps)

    @classmethod
    def read_file(cls, path: Path, secret: str) -> Self:
        secretb = secret.encode("ascii")

        storage: OtpsStorage = json.loads(path.read_text(encoding="ascii"), cls=BinaryDecoder)
        kdf_config = storage["kdf_config"]
        encrypted = storage["otps_encrypted"]
        key = pwhash.argon2i.kdf(SecretBox.KEY_SIZE, secretb, **kdf_config)
        box = SecretBox(key)
        plaintext = box.decrypt(encrypted)
        uris = json.loads(plaintext.decode("utf-8"))
        otps = [pyotp.parse_uri(uri) for uri in uris]

        return cls(path, kdf_config, key, otps)

    def write_file(self) -> None:
        assert self.key is not None
        box = SecretBox(self.key)
        plaintext = json.dumps([otp.provisioning_uri() for otp in self.otps]).encode("utf-8")
        encrypted = box.encrypt(plaintext)

        storage: OtpsStorage = {
            "kdf_config": self.kdf_config,
            "otps_encrypted": encrypted,
        }
        text_storage = json.dumps(storage, cls=BinaryEncoder)
        write_file(text_storage, self.path, "wt", encoding="ascii")

    def add_otp(self, otp: pyotp.OTP) -> None:
        self.otps.append(otp)

    def remove_otp(self, index: int) -> pyotp.OTP:
        return self.otps.pop(index)

    def _make_table(self):
        table = Table(title="One-time passwords (press ctrl-c to quit)")

        table.add_column("ID")
        table.add_column("Name")
        table.add_column("Issuer")
        table.add_column("Token")
        table.add_column("Seconds remaining")

        for i, otp in enumerate(self.otps):
            time_remaining = otp.interval - datetime.now().timestamp() % otp.interval
            table.add_row(str(i), otp.name, otp.issuer, otp.now(), f"{time_remaining:.1f}")

        return table

    def live_table(self) -> None:
        if self.otps:
            with Live(self._make_table(), screen=True, auto_refresh=False) as live:
                while True:
                    sleep(1)
                    live.update(self._make_table(), refresh=True)
        else:
            print("No OTPs available")

    def print_table(self) -> None:
        table = self._make_table()
        console = Console()
        console.print(table)

    def get_by_id(self, otp_id: int) -> pyotp.OTP:
        return self.otps[otp_id]


def get_secret(prompt: str, secret: Optional[str], repeat: bool) -> str:
    if secret is None:
        secret = getpass(f"{prompt}: ")
        if repeat:
            secret_repeat = getpass(f"{prompt} (repeat): ")
            if secret != secret_repeat:
                raise ValueError("Passwords don't match")

    try:
        secret.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("secret must be ASCII") from None

    return secret


def read_qr_code(path: Path, preprocess: bool = True) -> List[bytes]:
    from PIL import Image, ImageEnhance, ImageOps
    from pyzbar.pyzbar import decode

    with Image.open(path) as im:
        if im.mode == "LA":
            im = im.convert("RGBA")

        if im.mode == "RGBA":
            # Since we don't know what part of the image is transparent
            # we composite it on a gray image and adjust the contrast.
            # This should work no matter the white, the black
            # or the outside part of the qr code image is transparent.
            background = Image.new("RGBA", im.size, (128, 128, 128, 255))
            im = Image.alpha_composite(background, im)
            im = im.convert("RGB")
            im = ImageOps.autocontrast(im)

        if im.mode != "RGB":
            logging.debug("Image file is not RGB, but %s", im.mode)

        results = decode(im)
        if results:
            return [r.data for r in results]

        x, y = im.size
        for scale in [0.25, 0.5, 2, 4]:
            image_scaled = im.resize((int(x * scale), int(y * scale)))
            results = decode(image_scaled)
            if results:
                return [r.data for r in results]

            for sharpness in [0.25, 0.5, 2, 4]:
                sharpener = ImageEnhance.Sharpness(image_scaled)
                image_scaled_sharp = sharpener.enhance(sharpness)
                results = decode(image_scaled_sharp)
                print(scale, sharpness)
                if results:
                    return [r.data for r in results]

    return []


def read_qr_code_screen() -> List[bytes]:
    import mss
    from PIL import Image
    from pyzbar.pyzbar import decode

    results: List[bytes] = []
    with mss.mss() as sct:
        for monitor in sct.monitors[1:]:
            sct_img = sct.grab(monitor)
            img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
            results.extend(r.data for r in decode(img))

    return results


def base32_arg(s: str) -> str:
    try:
        base64.b32decode(s, casefold=True)
    except binascii.Error:
        msg = f"{s} is not valid base32"
        raise ArgumentTypeError(msg) from None

    return s


def mapping_arg(d: Dict[str, T]) -> Callable[[str], T]:
    def inner(obj: str) -> T:
        try:
            return d[obj]
        except KeyError:
            msg = f"Must be one of {', '.join(d)}"
            raise ArgumentTypeError(msg) from None

    return inner


def cmd_show(parser: ArgumentParser, args: Namespace, otpman: OTP) -> int:
    otpman.key = None  # key is not used anymore, forget it

    if args.exit:
        otpman.print_table()
    else:
        try:
            otpman.live_table()
        except KeyboardInterrupt:
            print("Interrupted")

    return 0


def otp_to_json(otp: pyotp.OTP) -> Dict[str, Any]:
    if isinstance(otp, pyotp.TOTP):
        return {
            "type": type(otp).__name__,
            "secret": otp.secret,
            "name": otp.name,
            "issuer": otp.issuer,
            "digits": otp.digits,
            "digest": otp.digest().name,
            "interval": otp.interval,
        }
    elif isinstance(otp, pyotp.HOTP):
        return {
            "type": type(otp).__name__,
            "secret": otp.secret,
            "name": otp.name,
            "issuer": otp.issuer,
            "digits": otp.digits,
            "digest": otp.digest().name,
            "initial_count": otp.initial_count,
        }
    else:
        raise TypeError()


def cmd_export(parser: ArgumentParser, args: Namespace, otpman: OTP) -> int:
    if args.format == "url":
        with StdoutFile(args.out, "xt", encoding="utf-8") as fw:
            for otp in otpman.otps:
                fw.write(f"{otp.provisioning_uri()}\n")
    elif args.format == "json":
        with StdoutFile(args.out, "xt", encoding="utf-8") as fw:
            out = [otp_to_json(otp) for otp in otpman.otps]
            json.dump(out, fw)
    elif args.format == "csv":
        with StdoutFile(args.out, "xt", encoding="utf-8", newline="") as fw:
            fieldnames = ["type", "secret", "name", "issuer", "digits", "digest", "interval", "initial_count"]
            writer = csv.DictWriter(fw, fieldnames)
            writer.writeheader()
            for otp in otpman.otps:
                # DictWriter treats None values like missing values and replaces them with a empty string
                writer.writerow(otp_to_json(otp))

    return 0


def cmd_change_password(parser: ArgumentParser, args: Namespace, otpman: OTP) -> int:
    new_secret = get_secret("Password (new)", args.secret_new, repeat=True)
    kdf_config, key = otpman.get_new_key(new_secret, args.opslimit, args.memlimit)
    otpman.kdf_config = kdf_config
    otpman.key = key
    otpman.write_file()
    print("Changed password")
    return 0


def cmd_remove(parser: ArgumentParser, args: Namespace, otpman: OTP) -> int:
    try:
        otp = otpman.remove_otp(args.id)
    except IndexError:
        print(f"Invalid OTP id: {args.id}")
        return 1
    else:
        otpman.write_file()
        print(f"OTP ID={args.id} Name={otp.name} Issuer={otp.issuer} removed")
        return 0


def cmd_screenshot_qr(parser: ArgumentParser, args: Namespace, otpman: OTP) -> int:
    sleep(args.delay)

    results = read_qr_code_screen()

    if not results:
        parser.error("No QR code could be found on the screen")

    modified = False
    for data in results:
        uri = data.decode("ascii")

        try:
            otp = pyotp.parse_uri(uri)
        except ValueError as e:
            print(f"{e}: {uri}")
        else:
            otpman.add_otp(otp)
            modified = True
            print(f"OTP Name={otp.name} Issuer={otp.issuer} added")

    if modified:
        otpman.write_file()
        return 0
    else:
        return 1


def cmd_add_qr(parser: ArgumentParser, args: Namespace, otpman: OTP) -> int:
    try:
        results = read_qr_code(args.qr_path)
    except FileNotFoundError:
        parser.error(f"--qr-path `{args.qr_path}` not found")

    if not results:
        parser.error("No QR code could be found in the image")

    modified = False
    for data in results:
        uri = data.decode("ascii")

        try:
            otp = pyotp.parse_uri(uri)
        except ValueError as e:
            print(f"{e}: {uri}")
        else:
            otpman.add_otp(otp)
            modified = True
            print(f"OTP Name={otp.name} Issuer={otp.issuer} added")

    if modified:
        otpman.write_file()
        return 0
    else:
        return 1


def cmd_show_qr(parser: ArgumentParser, args: Namespace, otpman: OTP) -> int:
    import qrcode

    try:
        otp = otpman.get_by_id(args.id)
    except IndexError:
        parser.error(f"Invalid ID {args.id}")

    uri = otp.provisioning_uri()

    qr = qrcode.QRCode()
    qr.add_data(uri)
    qr.print_ascii()
    return 0


def cmd_add_uri(parser: ArgumentParser, args: Namespace, otpman: OTP) -> int:
    try:
        otp = pyotp.parse_uri(args.uri)
    except ValueError as e:
        parser.error(str(e))

    otpman.add_otp(otp)
    otpman.write_file()
    print("OTP added")
    return 0


def cmd_add_totp(parser: ArgumentParser, args: Namespace, otpman: OTP) -> int:
    kwargs = {
        "digits": args.digits,
        "digest": args.digest,
        "name": args.name,
        "issuer": args.issuer,
        "interval": args.interval,
    }

    if args.secret:
        otp = pyotp.TOTP(args.secret, **kwargs)
        otpman.add_otp(otp)
    elif args.secret_hex:
        otp = pyotp.TOTP(hex_to_base32(args.secret_hex), **kwargs)
        otpman.add_otp(otp)

    otpman.write_file()
    print("TOTP added")
    return 0


def cmd_add_hotp(parser: ArgumentParser, args: Namespace, otpman: OTP) -> int:
    kwargs = {
        "initial_count": args.initial_count,
        "digits": args.digits,
        "digest": args.digest,
        "name": args.name,
        "issuer": args.issuer,
    }

    if args.secret:
        otp = pyotp.HOTP(args.secret, **kwargs)
        otpman.add_otp(otp)
    elif args.secret_hex:
        otp = pyotp.HOTP(hex_to_base32(args.secret_hex), **kwargs)
        otpman.add_otp(otp)

    otpman.write_file()
    print("HOTP added")
    return 0


def main():
    DEFAULT_DIGITS = 6
    DEFAULT_INTERVAL = 30
    DEFAULT_INITIAL_COUNT = 0
    DEFAULT_FILENAME = "otp.json"
    DEFAULT_EXPORT_FORMAT = "url"

    DEFAULT_PATH = Path(user_data_dir(APPNAME, APPAUTHOR)) / DEFAULT_FILENAME

    digests = {
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print debug information",
    )
    parser.add_argument(
        "--path",
        type=Path,
        metavar="PATH",
        default=DEFAULT_PATH,
        help="Path to the file where the secrets are stored.",
    )
    parser.add_argument(
        "--secret",
        type=str,
        metavar="ASCII-STRING",
        help="Password to encrypt OTP file. Needs to be ASCII. If not specified it will show a input prompt.",
    )

    subparsers = parser.add_subparsers(dest="action", required=False)

    parser_show = subparsers.add_parser("show", help="Show OTP tokens", formatter_class=ArgumentDefaultsHelpFormatter)
    parser_show.add_argument(
        "--exit",
        action="store_true",
        help="Print tokens and exit. Otherwise show a live refreshing table.",
    )
    parser_show.set_defaults(func=cmd_show)

    parser_export = subparsers.add_parser(
        "export",
        help="Export OTP secrets (not tokens) to file or print to screen",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser_export.add_argument(
        "--format",
        choices=("url", "csv", "json"),
        default=DEFAULT_EXPORT_FORMAT,
        help="Export file format",
    )
    parser_export.add_argument(
        "--out",
        type=Path,
        metavar="PATH",
        help="Write exported secrets to path. Otherwise they will be printed.",
    )
    parser_export.set_defaults(func=cmd_export)

    parser_password = subparsers.add_parser(
        "change-password", help="Change password secrets database file", formatter_class=ArgumentDefaultsHelpFormatter
    )
    parser_password.add_argument(
        "--secret-new",
        type=str,
        metavar="ASCII-STRING",
        help="New password. If not specified it will show a input prompt.",
    )
    parser_password.add_argument(
        "--opslimit",
        type=int,
        metavar="N",
        default=DEFAULT_OPSLIMIT,
        help="Specifies the KDF operations cost for new files or for --action change-password",
    )
    parser_password.add_argument(
        "--memlimit",
        type=int,
        metavar="N",
        default=DEFAULT_MEMLIMIT,
        help="Specifies the KDF memory cost for new files or for --action change-password",
    )
    parser_password.set_defaults(func=cmd_change_password)

    parser_remove = subparsers.add_parser(
        "remove", help="Remove OTP from database", formatter_class=ArgumentDefaultsHelpFormatter
    )
    parser_remove.add_argument(
        "--id",
        type=int,
        metavar="N",
        required=True,
        help="OTP ID to remove. The ID is shown when using show command.",
    )
    parser_remove.set_defaults(func=cmd_remove)

    parser_screenshot_qr = subparsers.add_parser(
        "screenshot-qr",
        help="Add OTP to database by taking a screenshot and scan for QR codes.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser_screenshot_qr.add_argument(
        "--delay",
        metavar="N",
        type=float,
        default=0,
        help="Delay screenshot by N seconds.",
    )
    parser_screenshot_qr.set_defaults(func=cmd_screenshot_qr)

    parser_add_qr = subparsers.add_parser(
        "add-qr",
        help="Add OTP to database by reading a QR code from a image file.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser_add_qr.add_argument("--qr-path", type=Path, metavar="PATH", required=True, help="Path to QR code file")
    parser_add_qr.set_defaults(func=cmd_add_qr)

    parser_show_qr = subparsers.add_parser(
        "show-qr",
        help="Print OTP QR Code to terminal.",
        formatter_class=ArgumentDefaultsHelpFormatter,
    )
    parser_show_qr.add_argument("--id", type=int, metavar="N", required=True, help="OTD ID to show QR code for")
    parser_show_qr.set_defaults(func=cmd_show_qr)

    parser_add_uri = subparsers.add_parser(
        "add-uri", help="Add OTP to database by otpauth URI", formatter_class=ArgumentDefaultsHelpFormatter
    )
    parser_add_uri.add_argument("--uri", required=True, help="OTP otpauth://... URI")
    parser_add_uri.set_defaults(func=cmd_add_uri)

    parser_add_totp = subparsers.add_parser(
        "add-totp", help="Add Time-based one-time password (TOTP)", formatter_class=ArgumentDefaultsHelpFormatter
    )
    group = parser_add_totp.add_mutually_exclusive_group(required=True)
    group.add_argument("--secret", type=base32_arg, metavar="BASE32-STRING", help="Add TOPT using base32 secret")
    group.add_argument("--secret-hex", metavar="HEX-STRING", help="Add TOPT using hex secret")
    parser_add_totp.add_argument(
        "--digits",
        type=int,
        metavar="N",
        default=DEFAULT_DIGITS,
        help="Number of digits of the token. Some apps expect this to be 6 digits, others support more.",
    )
    parser_add_totp.add_argument(
        "--digest",
        type=mapping_arg(digests),
        default="sha1",
        choices=digests.keys(),
        help="Digest function to use in the HMAC.",
    )
    parser_add_totp.add_argument("--name", type=str, metavar="TEXT", default=None, help="Account name.")
    parser_add_totp.add_argument("--issuer", type=str, metavar="TEXT", default=None, help="Issuer.")
    parser_add_totp.add_argument(
        "--interval", type=int, metavar="N", default=DEFAULT_INTERVAL, help="Time interval in seconds"
    )
    parser_add_totp.set_defaults(func=cmd_add_totp)

    parser_add_hotp = subparsers.add_parser(
        "add-hotp", help="Add HMAC-based one-time password (HOTP)", formatter_class=ArgumentDefaultsHelpFormatter
    )
    group = parser_add_hotp.add_mutually_exclusive_group(required=True)
    group.add_argument("--secret", type=base32_arg, metavar="BASE32-STRING", help="Add HOTP using base32 secret")
    group.add_argument("--secret-hex", metavar="HEX-STRING", help="Add HOTP using hex secret")
    parser_add_hotp.add_argument(
        "--digits",
        type=int,
        metavar="N",
        default=DEFAULT_DIGITS,
        help="Number of digits of the token. Some apps expect this to be 6 digits, others support more.",
    )
    parser_add_hotp.add_argument(
        "--digest",
        type=mapping_arg(digests),
        default="sha1",
        choices=digests.keys(),
        help="Digest function to use in the HMAC.",
    )
    parser_add_hotp.add_argument("--name", type=str, default=None, help="Account name.")
    parser_add_hotp.add_argument("--issuer", type=str, default=None, help="Issuer.")
    parser_add_hotp.add_argument(
        "--initial-count",
        type=int,
        metavar="N",
        default=DEFAULT_INITIAL_COUNT,
        help="Starting HMAC counter value",
    )
    parser_add_hotp.set_defaults(func=cmd_add_hotp)

    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    args.path.parent.mkdir(parents=True, exist_ok=True)

    if args.path.exists():
        try:
            secret = get_secret("Password", args.secret, repeat=False)
        except ValueError as e:
            parser.error(str(e))
        try:
            otpman = OTP.read_file(args.path, secret)
        except CryptoError as e:
            parser.error(str(e))
    else:
        try:
            secret = get_secret("Password", args.secret, repeat=True)
        except ValueError as e:
            parser.error(str(e))
        otpman = OTP.new(args.path, secret, args.opslimit, args.memlimit)
        otpman.write_file()
        print("Created new OTP file")

    if args.action is None:
        args.exit = False
        cmd_show(parser, args, otpman)
    else:
        args.func(parser, args, otpman)


if __name__ == "__main__":
    main()
