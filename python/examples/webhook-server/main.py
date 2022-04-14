# std imports
from http.server import HTTPServer, BaseHTTPRequestHandler
from http import HTTPStatus
from typing import Mapping

# third-party imports
import requests
from truelayer_signing import HttpMethod, extract_jws_header, verify_with_jkws

HOOK_PATH: str = "/hook/d7a2c49d-110a-4ed2-a07d-8fdb3ea6424b"


class HookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == HOOK_PATH:
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)

            try:
                res = hook_handler(self.path, self.headers, body.decode())
                self.send_response(res)
            except Exception as err:
                print(f"Error: {err}")
                self.send_response(HTTPStatus.UNAUTHORIZED)
            finally:
                self.end_headers()


def hook_handler(path: str, headers: Mapping[str, str], body: str) -> HTTPStatus:
    # extract tl_signature
    try:
        tl_signature = headers["Tl-Signature"]
    except KeyError:
        raise ValueError("Missing Tl-Signature Headers")

    # extract and ensure jku is an expected TrueLayer url
    jws_header = extract_jws_header(headers["Tl-Signature"])
    jku = jws_header["jku"]
    valid_jkus = ["https://webhooks.truelayer.com/.well-known/jwks",
                  "https://webhooks.truelayer-sandbox.com/.well-known/jwks"]
    if all(url != jku for url in valid_jkus):
        raise ValueError(f"Unpermitted jku {jku}")

    # fetch jkws
    res = requests.get(jku)
    res.raise_for_status()
    keys = res.json()["keys"]
    jwks = next(filter(lambda x: x["kid"] == jws_header["kid"], keys))

    # verify signature using the jkws
    res = verify_with_jkws(jwks) \
        .set_method(HttpMethod.POST) \
        .set_path(path) \
        .add_headers(headers) \
        .set_body(body) \
        .verify(tl_signature)

    return HTTPStatus.NO_CONTENT if res else HTTPStatus.UNAUTHORIZED


def run():
    PORT = 7000
    server_address = ('localhost', PORT)
    server = HTTPServer(server_address, HookHandler)
    print(f"Server running on port {PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run()