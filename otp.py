"""OTP CLI"""

import base64
import binascii
import json
import logging
import time
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser
from datetime import datetime
from getpass import getpass
from pathlib import Path
from typing import List, Optional, Tuple, TypedDict

import pyotp
from genutility.atomic import write_file
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
                    time.sleep(1)
                    live.update(self._make_table(), refresh=True)
        else:
            print("No OTPs available")

    def print_table(self) -> None:
        table = self._make_table()
        console = Console()
        console.print(table)


def get_secret(prompt: str, secret: str, repeat: bool) -> str:
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


def main():
    DEFAULT_DIGITS = 6
    DEFAULT_INTERVAL = 30
    DEFAULT_INITIAL_COUNT = 0
    DEFAULT_FILENAME = "otp.json"

    DEFAULT_PATH = Path(user_data_dir(APPNAME, APPAUTHOR)) / DEFAULT_FILENAME

    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        "--action",
        choices=(
            "show",
            "add-uri",
            "add-qr-code",
            "add-qr-code-screen",
            "add-totp",
            "add-hotp",
            "remove",
            "export",
            "change-password",
        ),
        default="show",
        help="Action to chose.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print debug information",
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=DEFAULT_PATH,
        help="Path to the file where the secrets are stored.",
    )
    parser.add_argument(
        "--secret",
        type=str,
        help="Password to encrypt OTP file. Needs to be ASCII. If not specified it will show a input prompt.",
    )
    parser.add_argument(
        "--secret-new",
        type=str,
        help="Use to set new password for --action change-password",
    )
    parser.add_argument(
        "--opslimit",
        type=int,
        default=DEFAULT_OPSLIMIT,
        help="Specifies the opslimit for new files or for --action change-password",
    )
    parser.add_argument(
        "--memlimit",
        type=int,
        default=DEFAULT_MEMLIMIT,
        help="Specifies the memlimit for new files or for --action change-password",
    )
    parser.add_argument(
        "--exit",
        action="store_true",
        help="Print the tokens for --action show and exit. Otherwise show a live refreshing table.",
    )
    parser.add_argument(
        "--id",
        type=int,
        help="OTP ID for --action remove. The ID is shown when using --action show.",
    )

    parser.add_argument("--uri", help="OTP otpauth://... URI for --action add-uri.")
    parser.add_argument("--qr-path", type=Path, help="Path to QR code file")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--secret-base32", help="Add TOPT/HOTP by base32 secret with --action add-totp/add-hotp")
    group.add_argument("--secret-hex", help="Add TOPT/HOTP by hex secret with --action add-totp/add-hotp")

    parser.add_argument(
        "--digits",
        type=int,
        default=DEFAULT_DIGITS,
        help="TOPT/HOTP: Number of integers in the OTP. Some apps expect this to be 6 digits, others support more.",
    )
    parser.add_argument(
        "--digest",
        type=str,
        default="sha1",
        choices=("sha1", "sha256", "sha512"),
        help="TOPT/HOTP: Digest function to use in the HMAC.",
    )
    parser.add_argument("--name", type=str, default=None, help="TOPT/HOTP: Account name.")
    parser.add_argument("--issuer", type=str, default=None, help="TOPT/HOTP: Issuer.")
    parser.add_argument(
        "--interval", type=int, default=DEFAULT_INTERVAL, help="Time interval in seconds for --action add-totp."
    )
    parser.add_argument(
        "--initial-count",
        type=int,
        default=DEFAULT_INITIAL_COUNT,
        help="Starting HMAC counter value for --action add-hotp.",
    )

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

    if args.action == "show":
        if args.uri or args.secret_base32 or args.secret_hex:
            parser.error("Use --action add with --uri, --secret-base32 or --secret-hex arguments")

        otpman.key = None  # key is not used anymore, forget it

        if args.exit:
            otpman.print_table()
        else:
            try:
                otpman.live_table()
            except KeyboardInterrupt:
                print("Interrupted")

    elif args.action == "export":
        for otp in otpman.otps:
            print(otp.provisioning_uri())

    elif args.action == "change-password":
        new_secret = get_secret("Password (new)", args.secret_new, repeat=True)
        kdf_config, key = otpman.get_new_key(new_secret, args.opslimit, args.memlimit)
        otpman.kdf_config = kdf_config
        otpman.key = key
        otpman.write_file()
        print("Changed password")

    elif args.action == "remove":
        if args.id is None:
            parser.error("--id required for --action remove")

        try:
            otp = otpman.remove_otp(args.id)
        except IndexError:
            print(f"Invalid OTP id: {args.id}")
        else:
            otpman.write_file()
            print(f"OTP ID={args.id} Name={otp.name} Issuer={otp.issuer} removed")

    elif args.action == "add-uri":
        if args.uri is None:
            parser.error("--action add-uri requires --uri")

        try:
            otp = pyotp.parse_uri(args.uri)
        except ValueError as e:
            parser.error(str(e))

        otpman.add_otp(otp)
        otpman.write_file()
        print("OTP added")

    elif args.action == "add-qr-code":
        if args.qr_path is None:
            parser.error("--action add-qr-code requires --qr-path")

        results = read_qr_code(args.qr_path)

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

    elif args.action == "add-qr-code-screen":

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

    elif args.action == "add-totp":
        kwargs = {
            "digits": args.digits,
            "digest": args.digest,
            "name": args.name,
            "issuer": args.issuer,
            "interval": args.interval,
        }

        if args.secret_base32:
            otp = pyotp.TOTP(args.base32_secret, **kwargs)
            otpman.add_otp(otp)
        elif args.secret_hex:
            otp = pyotp.TOTP(hex_to_base32(args.secret_hex), **kwargs)
            otpman.add_otp(otp)
        else:
            parser.error("For --action add-totp either --secret-base32 or --secret-hex is required")

        otpman.write_file()
        print("TOTP added")

    elif args.action == "add-hotp":
        kwargs = {
            "initial_count": args.initial_count,
            "digits": args.digits,
            "digest": args.digest,
            "name": args.name,
            "issuer": args.issuer,
        }

        if args.secret_base32:
            otp = pyotp.HOTP(args.base32_secret, **kwargs)
            otpman.add_otp(otp)
        elif args.secret_hex:
            otp = pyotp.HOTP(hex_to_base32(args.secret_hex), **kwargs)
            otpman.add_otp(otp)
        else:
            parser.error("For --action add-hotp either --secret-base32 or --secret-hex is required")

        otpman.write_file()
        print("HOTP added")

    else:
        assert False


if __name__ == "__main__":
    main()
