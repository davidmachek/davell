import base64

def decode_base32_to_bytes(s: str) -> bytes:
    s_clean = s.strip().replace(" ", "").upper()
    return base64.b32decode(s_clean, casefold=True)

def to_base64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode('ascii')

def from_base64url_nopad(s: str) -> bytes:
    pad = '=' * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def encode_id(base32_str: str) -> str:
    b = decode_base32_to_bytes(base32_str)
    return to_base64url_nopad(b)

def decode_token(s: str) -> str:
    b = from_base64url_nopad(s)
    return base64.b32encode(b).decode('ascii').lower()
