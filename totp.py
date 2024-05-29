import base64
from time import time
import hmac


TIME_STEP = 30
EPOCH = 0
HOTP_LENGTH = 6


def get_totp(secret: str) -> int:
    timestamp = (int(time()) - EPOCH) // TIME_STEP
    return _get_hotp(timestamp, secret)


def _get_hotp(timestamp: int, secret: str) -> int:
    _hashed = hmac.new(base64.b32decode(secret.upper() + '=' * ((8 - len(secret)) % 8)), timestamp.to_bytes(length=8), 'sha1').digest()
    return _truncate(_hashed)


def _truncate(hashed: bytes) -> int:
    # Get the last 4 bits of the hmac as offset
    offset = hashed[-1] % 16
    # Get the last 31 bits of the truncated hmac, followed by trimming it to the specified length
    return int.from_bytes(hashed[offset : offset + 4]) % 2 ** 31 % 10 ** HOTP_LENGTH


if __name__ == "__main__":
    print(get_totp(secret="LFXXKIDSMV3GK4TTMVSCA2LUEE"))
