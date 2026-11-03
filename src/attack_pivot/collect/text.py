"""URL canonicalisation and text extraction for collected reports."""

import hashlib
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TRACKING_PARAMS = {"fbclid", "gclid", "mc_cid", "mc_eid", "ref", "ref_src", "source"}
MIN_TEXT_CHARS = 500  # shorter than this is a stub, a redirect page or an error page


def canonical_url(url):
    """
    Stable form of a URL for dedupe: lowercase scheme and host, no fragment, no default port,
    no tracking parameters, sorted query, no trailing slash (except the root).
    """
    parts = urlsplit(url.strip())
    scheme, host = parts.scheme.lower(), (parts.hostname or "").lower()
    port = parts.port
    netloc = host if port in (None, 80, 443) else f"{host}:{port}"
    query = urlencode(
        sorted(
            (k, v)
            for k, v in parse_qsl(parts.query, keep_blank_values=True)
            if not k.lower().startswith("utm_") and k.lower() not in TRACKING_PARAMS
        )
    )
    path = re.sub(r"/{2,}", "/", parts.path or "/")
    if len(path) > 1:
        path = path.rstrip("/")
    return urlunsplit((scheme, netloc, path, query, ""))


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def extract_text(content, content_type=None, url=""):
    """
    Readable text from a fetched body: PDF, HTML or plain text. Uses the API's own extractors so
    the text the triage sees is the text the extraction job would see.

    :param bytes content:
    :rtype: str
    """
    from attack_flow_api.services.html_extraction import extract_readable_text_from_html
    from attack_flow_api.services.pdf_extraction import extract_pdf_text_content
    from attack_flow_api.services.text_normalization import normalize_raw_text

    kind = (content_type or "").split(";")[0].strip().lower()
    if (
        content[:5] == b"%PDF-"
        or kind == "application/pdf"
        or url.lower().endswith(".pdf")
    ):
        return extract_pdf_text_content(content).normalized_text
    decoded = content.decode("utf-8", errors="replace").replace("\x00", "")
    if kind in ("text/plain", "text/markdown") or (
        not kind and not re.search(r"<\s*(html|body|p|div)\b", decoded[:2000], re.I)
    ):
        return normalize_raw_text(decoded).text
    return extract_readable_text_from_html(decoded).normalized_text
