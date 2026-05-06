# GitHub Repository Settings

## Branch Protection

The repository should protect `main` with the CI verify gate before merge.

Recommended settings:

- Require status checks before merging: enabled
- Required check: `Verify`
- Require branches to be up to date before merging: enabled
- Block force pushes: enabled
- Block branch deletion: enabled

Automation note: applying this through the GitHub API requires repository admin permission. The local credential available in this workspace can push commits, but returned `403` when attempting to update branch protection.

## Releases

Pushing a tag matching `v*` runs `.github/workflows/release.yml`.

The workflow:

- Runs `py .\pii_radar.py verify`
- Generates release notes with `py .\pii_radar.py release-notes`
- Builds a clean ZIP excluding data, reports, logs, inboxes, backups, and caches
- Uploads the ZIP as a workflow artifact
- Publishes a GitHub Release with the ZIP attached when triggered by a `v*` tag
