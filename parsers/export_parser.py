import hashlib
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Dict, List


class ExportParser:
    def parse_file(self, path: Path) -> List[Dict[str, Any]]:
        suffix = path.suffix.lower()

        if suffix == ".json":
            return self._parse_json(path)
        if suffix in (".html", ".htm"):
            return self._parse_html(path)
        if suffix in (".txt", ".log", ".csv"):
            return self._parse_text(path)

        return []

    def _parse_json(self, path: Path) -> List[Dict[str, Any]]:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))

        messages = self._extract_json_messages(data)
        parsed = []

        for idx, item in enumerate(messages):
            if not isinstance(item, dict):
                continue

            text = self._message_text(item)
            if not text.strip():
                continue

            author = self._author(item)
            timestamp = item.get("date") or item.get("timestamp") or item.get("createdAt") or item.get("time") or ""
            msg_id = str(item.get("id") or item.get("message_id") or self._stable_hash(path, idx, text))
            platform = self._guess_platform_json(data, item)

            parsed.append({
                "message_id": msg_id,
                "platform": platform,
                "source_file": str(path),
                "source_file_name": path.name,
                "timestamp": str(timestamp),
                "author": author,
                "text": text,
            })

        return parsed

    def _parse_html(self, path: Path) -> List[Dict[str, Any]]:
        html = path.read_text(encoding="utf-8", errors="replace")
        parser = _VisibleTextParser()
        parser.feed(html)

        chunks = self._chunk_lines(parser.lines)
        parsed = []

        for idx, text in enumerate(chunks):
            if not text.strip():
                continue

            parsed.append({
                "message_id": self._stable_hash(path, idx, text),
                "platform": "html_export",
                "source_file": str(path),
                "source_file_name": path.name,
                "timestamp": "",
                "author": "",
                "text": text,
            })

        return parsed

    def _parse_text(self, path: Path) -> List[Dict[str, Any]]:
        content = path.read_text(encoding="utf-8", errors="replace")
        lines = [line.strip() for line in content.splitlines() if line.strip()]

        chunks = self._chunk_lines(lines)
        parsed = []

        for idx, text in enumerate(chunks):
            parsed.append({
                "message_id": self._stable_hash(path, idx, text),
                "platform": "text_export",
                "source_file": str(path),
                "source_file_name": path.name,
                "timestamp": "",
                "author": "",
                "text": text,
            })

        return parsed

    def _extract_json_messages(self, data: Any) -> List[Any]:
        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            for key in ("messages", "result", "data", "items"):
                val = data.get(key)
                if isinstance(val, list):
                    return val

            if "message" in data or "content" in data or "text" in data:
                return [data]

        return []

    def _message_text(self, item: Dict[str, Any]) -> str:
        for key in ("text", "message", "content", "body"):
            if key in item:
                return self._to_text(item.get(key))

        embeds = item.get("embeds")
        if isinstance(embeds, list):
            parts = []
            for e in embeds:
                if isinstance(e, dict):
                    parts.append(str(e.get("title", "")))
                    parts.append(str(e.get("description", "")))
            return "\n".join(x for x in parts if x)

        return ""

    def _to_text(self, value: Any) -> str:
        if value is None:
            return ""

        if isinstance(value, str):
            return value

        if isinstance(value, list):
            parts = []
            for item in value:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    parts.append(str(item.get("text", "")))
                else:
                    parts.append(str(item))
            return "".join(parts)

        if isinstance(value, dict):
            return str(value.get("text", ""))

        return str(value)

    def _author(self, item: Dict[str, Any]) -> str:
        author = item.get("author")
        if isinstance(author, dict):
            return str(
                author.get("name")
                or author.get("username")
                or author.get("displayName")
                or author.get("id")
                or ""
            )

        return str(
            item.get("from")
            or item.get("from_id")
            or item.get("actor")
            or item.get("sender")
            or author
            or ""
        )

    def _guess_platform_json(self, root: Any, item: Dict[str, Any]) -> str:
        if isinstance(root, dict):
            if "guild" in root or "channel" in root:
                return "discord_json"
            if root.get("type") in ("personal_chat", "private_group", "public_group", "saved_messages"):
                return "telegram_json"

        if "from_id" in item or "text_entities" in item:
            return "telegram_json"

        if isinstance(item.get("author"), dict) and "content" in item:
            return "discord_json"

        return "json_export"

    def _chunk_lines(self, lines: List[str], max_chars: int = 1200) -> List[str]:
        chunks = []
        current = ""

        for line in lines:
            clean = re.sub(r"\s+", " ", line).strip()
            if not clean:
                continue

            if len(current) + len(clean) + 1 > max_chars:
                if current:
                    chunks.append(current)
                current = clean
            else:
                current = (current + "\n" + clean).strip()

        if current:
            chunks.append(current)

        return chunks

    def _stable_hash(self, path: Path, idx: int, text: str) -> str:
        raw = f"{path.name}|{idx}|{text}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class _VisibleTextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.lines = []
        self._skip = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() in ("script", "style"):
            self._skip = True

    def handle_endtag(self, tag):
        if tag.lower() in ("script", "style"):
            self._skip = False

    def handle_data(self, data):
        if self._skip:
            return

        clean = re.sub(r"\s+", " ", data).strip()
        if clean:
            self.lines.append(clean)
