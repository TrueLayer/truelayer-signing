# std imports
from uuid import uuid4

# third-party imports
import requests
from requests import Response
from truelayer_signing import HttpMethod, sign_with_pem

# local imports
from .contants import ACCESS_TOKEN, KID, PRIVATE_KEY

# the base url to use
DEV_URL = "https://api.t7r.dev"
SBOX_URL = "https://api.truelayer-sandbox.com"
TL_BASE_URL: str = DEV_URL


def test_signature_endpoint():
    url = f"{TL_BASE_URL}/test-signature"
    idempotency_key = str(uuid4())
    body = f"body-{idempotency_key}"

    signature = sign_with_pem(KID, PRIVATE_KEY) \
        .set_method(HttpMethod.POST) \
        .set_path("/test-signature") \
        .add_header("Idempotency-Key", idempotency_key) \
        .add_header("X-Bar-Header", "abc123") \
        .set_body(body) \
        .sign()

    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json",
        "Idempotency-Key": idempotency_key,
        "X-Bar-Header": "abc123",
        "Tl-Signature": signature
    }

    res: Response = requests.post(url, headers=headers, data=body)
    try:
        res.raise_for_status()
        response_body = "✓"
    except:
        response_body = res.content.decode()
    print(f"{res.status_code} {response_body}")
