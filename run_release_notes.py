import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from core.reporting import build_report, write_json_report


FIELD_SEP = "\x1f"


def parse_args():
    parser = argparse.ArgumentParser(description="Generate release notes from git history")
    parser.add_argument("--since", default="", help="Git revision or tag to start after")
    parser.add_argument("--max-count", type=int, default=50, help="Maximum commits to include")
    return parser.parse_args()


def run_git(args):
    proc = subprocess.run(["git", *args], cwd=str(ROOT), text=True, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or "git command failed").strip())
    return proc.stdout.strip()


def latest_tag():
    try:
        return run_git(["describe", "--tags", "--abbrev=0"])
    except RuntimeError:
        return ""


def git_log_range(since):
    return f"{since}..HEAD" if since else "HEAD"


def parse_git_log(text):
    commits = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split(FIELD_SEP)
        if len(parts) != 4:
            continue
        full_sha, short_sha, date, subject = parts
        commits.append(
            {
                "sha": full_sha,
                "short_sha": short_sha,
                "date": date,
                "subject": subject,
            }
        )
    return commits


def collect_commits(since, max_count):
    rev = git_log_range(since)
    output = run_git(
        [
            "log",
            rev,
            f"--max-count={max_count}",
            "--date=short",
            f"--pretty=format:%H{FIELD_SEP}%h{FIELD_SEP}%ad{FIELD_SEP}%s",
        ]
    )
    return parse_git_log(output)


def render_markdown(commits, since):
    title = f"# Release Notes\n\n"
    scope = f"Range: `{git_log_range(since)}`\n\n"
    if not commits:
        return title + scope + "No commits found.\n"

    lines = [title, scope, "## Changes\n\n"]
    for commit in commits:
        lines.append(f"- `{commit['short_sha']}` {commit['date']} - {commit['subject']}\n")
    return "".join(lines)


def write_release_notes(since="", max_count=50):
    reports_dir = ROOT / "reports"
    effective_since = since or latest_tag()
    commits = collect_commits(effective_since, max_count)
    markdown = render_markdown(commits, effective_since)

    md_path = reports_dir / "release_notes.md"
    json_path = reports_dir / "release_notes.json"
    reports_dir.mkdir(parents=True, exist_ok=True)
    md_path.write_text(markdown, encoding="utf-8")

    report = build_report(
        name="release_notes",
        summary={
            "commit_count": len(commits),
            "since": effective_since,
            "range": git_log_range(effective_since),
            "max_count": max_count,
        },
        outputs={
            "markdown": str(md_path),
            "json": str(json_path),
        },
        data={
            "commits": commits,
        },
    )
    write_json_report(json_path, report)
    return md_path, json_path, report


def main():
    args = parse_args()
    md_path, json_path, report = write_release_notes(args.since, args.max_count)
    print("RELEASE_NOTES")
    print(f"status={report['status']}")
    print(f"commit_count={report['summary']['commit_count']}")
    print(f"range={report['summary']['range']}")
    print(f"markdown={md_path}")
    print(f"json={json_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
