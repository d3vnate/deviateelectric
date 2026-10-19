"""App Engine backend for deviateelectric.com.

Exposes POST /send-email, which:
  1. Validates the incoming quote-request payload.
  2. Verifies the reCAPTCHA v3 token against Google.
  3. Delivers the inquiry to the owner via Amazon SES (SendEmail API).

Stdlib only (urllib + hmac/hashlib for SigV4) so no requirements.txt is
needed. Credentials come from environment variables injected via Secret
Manager (see app.yaml):
  - AWS_ACCESS_KEY_ID
  - AWS_SECRET_ACCESS_KEY
  - AWS_SES_REGION      (default us-east-1)
  - RECAPTCHA_SECRET_KEY
Optional overrides:
  - CONTACT_EMAIL       (recipient, default donny@deviateelectric.com)
  - SENDER_ADDRESS      (SES-verified identity, default donny@deviateelectric.com)
  - RECAPTCHA_MIN_SCORE (default 0.5)
"""

import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("deviate-electric")

SES_ENDPOINT_TEMPLATE = "https://email.{region}.amazonaws.com"
RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify"

AWS_REGION = os.environ.get("AWS_SES_REGION", "us-east-1")
DEFAULT_CONTACT_EMAIL = "donny@deviateelectric.com"
DEFAULT_SENDER_ADDRESS = "donny@deviateelectric.com"
SENDER_DISPLAY_NAME = "Deviate Electric"
MIN_CAPTCHA_SCORE = float(os.environ.get("RECAPTCHA_MIN_SCORE", "0.5"))

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_RE = re.compile(r"^[\d\s()+.-]{7,20}$")

FIELD_LIMITS = {
    "name": 120,
    "phone": 40,
    "email": 120,
    "service": 80,
    "details": 2000,
    "captcha_token": 500,
}


class ApiError(Exception):
    """Raised when an upstream API call fails."""


def _clean(value, limit):
    """Coerce to stripped string capped at `limit` chars ('' for None)."""
    if value is None:
        return ""
    return str(value)[:limit].strip()


def _http_post_json(url, payload, headers=None, timeout=15):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for key, val in (headers or {}).items():
        req.add_header(key, val)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8") or "{}"
            return resp.status, json.loads(body)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise ApiError(f"{exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ApiError(str(exc.reason)) from exc


def _verify_recaptcha(token):
    """Return (passed, score).

    TEMPORARY DEV MODE: while RECAPTCHA_SECRET_KEY is not configured,
    verification is skipped (logged loudly). As soon as the secret exists
    in Secret Manager, enforcement turns back ON automatically — no code
    change needed.
    """
    secret = os.environ.get("RECAPTCHA_SECRET_KEY", "").strip()
    if not secret:
        log.warning("RECAPTCHA_SECRET_KEY not set — CAPTCHA VERIFICATION DISABLED (temporary)")
        return True, None
    if not token:
        return False, None
    try:
        _, result = _http_post_json(
            RECAPTCHA_VERIFY_URL, {"secret": secret, "response": token}
        )
    except ApiError as exc:
        log.warning("reCAPTCHA verification unreachable: %s", exc)
        return False, None
    score = result.get("score")
    passed = (
        bool(result.get("success"))
        and isinstance(score, (int, float))
        and score >= MIN_CAPTCHA_SCORE
    )
    return passed, score


def _build_subject(service, name):
    label = service or "General"
    return f"Quote request: {label} — {name}"


def _build_text(fields):
    lines = [
        "New quote request from deviateelectric.com",
        "",
        f"Name:      {fields['name']}",
        f"Phone:     {fields['phone']}",
    ]
    if fields["email"]:
        lines.append(f"Email:     {fields['email']}")
    lines += [
        f"Service:   {fields['service'] or '(unspecified)'}",
        "",
        "Details:",
        fields["details"] or "(none provided)",
        "",
        "-- sent via website quote form",
    ]
    return "\n".join(lines)


def _sign_sigv4(method, url, headers, body_bytes, region, service):
    """Minimal AWS Signature V4 signer (stdlib only). Mutates `headers`."""
    access_key = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    if not access_key or not secret_key:
        raise ApiError("AWS credentials are not configured")

    parsed = urllib.parse.urlsplit(url)
    amz_date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    date_stamp = amz_date[:8]
    canonical_uri = parsed.path or "/"
    canonical_query = parsed.query.replace("+", "%20")

    # Headers that participate in the signature must be present BEFORE
    # the canonical request is assembled.
    headers["host"] = parsed.netloc
    headers["x-amz-date"] = amz_date
    session_token = os.environ.get("AWS_SESSION_TOKEN", "").strip()
    if session_token:
        headers["x-amz-security-token"] = session_token

    signed_headers = sorted(h.lower() for h in headers)
    canonical_headers = "".join(f"{h}:{str(headers[h]).strip()}\n" for h in signed_headers)
    signed_headers_str = ";".join(signed_headers)
    payload_hash = hashlib.sha256(body_bytes).hexdigest()

    canonical_request = "\n".join([method, canonical_uri, canonical_query,
                                   canonical_headers, signed_headers_str, payload_hash])
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                                hashlib.sha256(canonical_request.encode()).hexdigest()])

    def _mac(key, msg):
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k_date = _mac(("AWS4" + secret_key).encode(), date_stamp)
    k_region = _mac(k_date, region)
    k_service = _mac(k_region, service)
    signing_key = _mac(k_service, "aws4_request")
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    authorization = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                     f"SignedHeaders={signed_headers_str}, Signature={signature}")
    headers["authorization"] = authorization
    return headers


def _send_via_ses(subject, text):
    """Send via the SES query protocol (form-encoded Action/Version params)."""
    sender = os.environ.get("SENDER_ADDRESS", DEFAULT_SENDER_ADDRESS).strip()
    recipient = os.environ.get("CONTACT_EMAIL", DEFAULT_CONTACT_EMAIL).strip()

    params = {
        "Action": "SendEmail",
        "Version": "2010-12-01",
        "Source": f"{SENDER_DISPLAY_NAME} <{sender}>",
        "Destination.ToAddresses.member.1": recipient,
        "Message.Subject.Charset": "UTF-8",
        "Message.Subject.Data": subject,
        "Message.Body.Text.Charset": "UTF-8",
        "Message.Body.Text.Data": text,
    }
    body_bytes = urllib.parse.urlencode(params).encode("utf-8")
    endpoint = SES_ENDPOINT_TEMPLATE.format(region=AWS_REGION)
    headers = {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}
    _sign_sigv4("POST", endpoint, headers, body_bytes, AWS_REGION, "ses")

    req = urllib.request.Request(endpoint, data=body_bytes, method="POST")
    for key, val in headers.items():
        if val:
            req.add_header(key.title(), val)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:2000]
        raise ApiError(f"SES responded with HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ApiError(str(exc.reason)) from exc


def _respond(start_response, status_code, payload):
    body = json.dumps(payload).encode("utf-8")
    start_response(
        f"{status_code} {'OK' if status_code == 200 else ''}".rstrip(),
        [("Content-Type", "application/json; charset=utf-8"),
         ("Cache-Control", "no-store")],
    )
    return [body]


def _handle_send_email(environ, start_response):
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
        raw = environ["wsgi.input"].read(length) if length > 0 else b""
        payload = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(payload, dict):
            raise ValueError
    except (ValueError, TypeError):
        return _respond(start_response, 400, {"ok": False, "error": "Invalid JSON body."})

    fields = {key: _clean(payload.get(key), FIELD_LIMITS[key]) for key in FIELD_LIMITS}

    if not fields["name"] or not fields["phone"]:
        return _respond(
            start_response, 400, {"ok": False, "error": "Name and phone are required."}
        )
    if not PHONE_RE.match(fields["phone"]):
        return _respond(
            start_response, 400, {"ok": False, "error": "That phone number looks off."}
        )
    if fields["email"] and not EMAIL_RE.match(fields["email"]):
        return _respond(
            start_response, 400, {"ok": False, "error": "That email address looks off."}
        )

    passed, score = _verify_recaptcha(fields["captcha_token"])
    if not passed:
        log.info("Rejected submission (captcha fail, score=%s)", score)
        return _respond(
            start_response, 403, {"ok": False, "error": "Security check failed. Please try again."}
        )

    try:
        _send_via_ses(_build_subject(fields["service"], fields["name"]), _build_text(fields))
    except Exception as exc:  # noqa: BLE001 - report anything that breaks dispatch
        log.exception("Failed to dispatch email (%s: %s)", type(exc).__name__, exc)
        return _respond(
            start_response,
            502,
            {"ok": False, "error": "We couldn't send your request right now. Please try again later."},
        )

    log.info("Quote request delivered (captcha score=%.2f)", score or 0.0)
    return _respond(start_response, 200, {"ok": True})


def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")

    if path == "/send-email":
        if method == "POST":
            return _handle_send_email(environ, start_response)
        return _respond(start_response, 405, {"ok": False, "error": "Method not allowed."})

    return _respond(start_response, 404, {"ok": False, "error": "Not found."})
