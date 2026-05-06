import copy
import re
from typing import Any


EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
TR_PHONE_RE = re.compile(r"(?<!\d)(?:\+?90\s*)?5\d{2}[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}(?!\d)")
TC_RE = re.compile(r"(?<!\d)\d{11}(?!\d)")
SECRET_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|passwd|authorization)\b\s*[:=]\s*['\"]?[^'\"\s,;]+"
)


def mask_text(text: str) -> str:
    if not isinstance(text, str):
        return text

    text = EMAIL_RE.sub(lambda m: _mask_email(m.group(0)), text)
    text = TR_PHONE_RE.sub(lambda m: _mask_middle(m.group(0), 4, 2), text)
    text = TC_RE.sub(lambda m: _mask_middle(m.group(0), 2, 2), text)
    text = SECRET_RE.sub(lambda m: m.group(1) + "=***MASKED***", text)
    return text


def _mask_email(value: str) -> str:
    user, _, domain = value.partition("@")
    if len(user) <= 2:
        user_masked = user[:1] + "***"
    else:
        user_masked = user[:2] + "***"
    return f"{user_masked}@{domain}"


def _mask_middle(value: str, keep_start: int, keep_end: int) -> str:
    clean = value.strip()
    if len(clean) <= keep_start + keep_end:
        return "***MASKED***"
    return clean[:keep_start] + "***" + clean[-keep_end:]


def sanitize_obj(obj: Any) -> Any:
    if isinstance(obj, str):
        return mask_text(obj)
    if isinstance(obj, list):
        return [sanitize_obj(x) for x in obj]
    if isinstance(obj, dict):
        result = {}
        for key, value in obj.items():
            low_key = str(key).lower()
            if any(k in low_key for k in ("password", "passwd", "secret", "token", "api_key", "authorization")):
                result[key] = "***MASKED***"
            else:
                result[key] = sanitize_obj(value)
        return result
    return obj


def sanitized_copy(obj: Any) -> Any:
    return sanitize_obj(copy.deepcopy(obj))
