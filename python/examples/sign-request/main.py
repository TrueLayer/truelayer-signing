# std imports
import os
from uuid import uuid4

# third-party imports
import json
import requests

from requests import Response
from truelayer_signing import HttpMethod, sign_with_pem

# load env vars
ACCESS_TOKEN = os.getenv("ACCESS_TOKEN")
KID = os.getenv("KID")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")

if not ACCESS_TOKEN:
    raise ValueError("ACCESS_TOKEN not in Environment Variables")
if not KID:
    raise ValueError("KID not in Environment Variables")
if not PRIVATE_KEY:
    raise ValueError("PRIVATE_KEY not in Environment Variables")

# the base url to use
TL_BASE_URL: str = "https://api.truelayer-sandbox.com"


def test_signature_endpoint():
    url = f"{TL_BASE_URL}/test-signature"
    idempotency_key = str(uuid4())

    # the request payload
    payload = {
        "amount_in_minor": 1,
        "currency": "GBP",
    }

    # Note: the body given to signaute must match the body given to the request.
    # to ensure the same body is used in both we convert to a string.
    body = json.dumps(payload, separators=(",", ":"))

    signature = (
        sign_with_pem(KID, PRIVATE_KEY)
        .set_method(HttpMethod.POST)
        .set_path("/test-signature")
        # Note: the Idempotency-Key header is required by tl
        .add_header("Idempotency-Key", idempotency_key)
        # This is a dummy header. All headers in the signature must be present
        # in the request.
        .add_header("X-Bar-Header", "abc123")
        .set_body(body)
        .sign()
    )

    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        # because we are supplying a string as the body to the request we must
        # explicitly let requests know that the content type is json
        "Content-Type": "application/json",
        "Idempotency-Key": idempotency_key,
        "X-Bar-Header": "abc123",
        "Tl-Signature": signature,
    }

    res: Response = requests.post(url, headers=headers, data=body)
    try:
        res.raise_for_status()
        response_body = "✓"
    except Exception:
        response_body = res.content.decode()
    print(f"{res.status_code} {response_body}")


if __name__ == "__main__":
    test_signature_endpoint()
