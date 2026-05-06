import re

EMAIL_RE = re.compile(r"([A-Za-z0-9._%+\-]{1,80})@([A-Za-z0-9.\-]{1,120}\.[A-Za-z]{2,20})")
PHONE_RE = re.compile(r"(?<!\d)(\+?\d[\d\s().\-]{7,22}\d)(?!\d)")
URL_RE = re.compile(r"\bhttps?://[^\s<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,20}\b", re.IGNORECASE)
LONG_RE = re.compile(r"\b[A-Za-z0-9_\-]{24,}\b")

def _keep_edges(value, left=2, right=2, mask="***"):
    text = "" if value is None else str(value)
    if len(text) <= left + right:
        return mask
    return f"{text[:left]}{mask}{text[-right:]}"

def mask_email(value):
    text = "" if value is None else str(value).strip()
    if "@" not in text:
        return _keep_edges(text, 1, 1)
    name, domain = text.split("@", 1)
    if not name:
        return f"***@{domain}"
    return f"{name[:1]}****@{domain}"

def mask_phone(value):
    raw = "" if value is None else str(value)
    digits = re.sub(r"\D+", "", raw)
    if len(digits) < 7:
        return _keep_edges(raw, 2, 1)
    prefix = "+" if raw.strip().startswith("+") else ""
    if len(digits) <= 10:
        return f"{prefix}{digits[:3]}***{digits[-3:]}"
    return f"{prefix}{digits[:4]}***{digits[-4:]}"

def mask_username(value):
    text = "" if value is None else str(value).strip()
    if text.startswith("@"):
        return "@" + _keep_edges(text[1:], 2, 2)
    return _keep_edges(text, 2, 2)

def mask_domain(value):
    text = "" if value is None else str(value).strip().lower()
    parts = text.split(".")
    if len(parts) < 2:
        return _keep_edges(text, 2, 2)
    root = parts[-2]
    tld = parts[-1]
    if len(parts) > 2:
        return f"*.{root}.{tld}"
    return f"{_keep_edges(root, 1, 1)}.{tld}"

def mask_url(value):
    text = "" if value is None else str(value).strip()
    m = re.match(r"^(https?://)([^/]+)(.*)$", text, re.IGNORECASE)
    if not m:
        return _keep_edges(text, 8, 4)
    scheme, host, path = m.groups()
    if path:
        return f"{scheme}{mask_domain(host)}/***"
    return f"{scheme}{mask_domain(host)}"

def mask_secret(value):
    return _keep_edges(value, 4, 4, "********")

def mask_value(value, value_type=None):
    text = "" if value is None else str(value).strip()
    kind = "" if value_type is None else str(value_type).lower().strip()

    if kind in ("email", "mail"):
        return mask_email(text)
    if kind in ("phone", "telefon", "gsm", "mobile"):
        return mask_phone(text)
    if kind in ("username", "user", "handle", "alias"):
        return mask_username(text)
    if kind in ("domain", "host"):
        return mask_domain(text)
    if kind in ("url", "link"):
        return mask_url(text)
    if kind in ("secret", "token", "key", "credential", "password"):
        return mask_secret(text)

    if EMAIL_RE.fullmatch(text):
        return mask_email(text)
    if URL_RE.fullmatch(text):
        return mask_url(text)
    if PHONE_RE.fullmatch(text):
        return mask_phone(text)
    if DOMAIN_RE.fullmatch(text):
        return mask_domain(text)
    if LONG_RE.fullmatch(text):
        return mask_secret(text)

    return _keep_edges(text, 3, 3)

def mask_text(text):
    masked = "" if text is None else str(text)
    masked = EMAIL_RE.sub(lambda m: mask_email(m.group(0)), masked)
    masked = URL_RE.sub(lambda m: mask_url(m.group(0)), masked)
    masked = PHONE_RE.sub(lambda m: mask_phone(m.group(0)), masked)
    masked = LONG_RE.sub(lambda m: mask_secret(m.group(0)), masked)
    return masked

def build_masked_snippet(text, start, end, radius=80):
    text = "" if text is None else str(text)
    safe_start = max(0, int(start) - radius)
    safe_end = min(len(text), int(end) + radius)
    snippet = text[safe_start:safe_end].strip()
    snippet = mask_text(snippet)
    if safe_start > 0:
        snippet = "... " + snippet
    if safe_end < len(text):
        snippet = snippet + " ..."
    return snippet

if __name__ == "__main__":
    print(mask_value("sample.person@example.com", "email"))
    print(mask_value("+905551112233", "phone"))
    print(mask_value("@sampleperson", "username"))
    print(mask_value("login.example.net", "domain"))
    print(mask_value("https://login.example.net/path/to/panel", "url"))
