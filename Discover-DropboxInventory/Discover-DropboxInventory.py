#!/usr/bin/env python3
"""
Discover-DropboxInventory.py

Full file-level inventory of a Dropbox Business team using the Dropbox API.
Produces an exact per-file manifest plus summary reports for migration scoping.

See README.md for full setup instructions and troubleshooting.

SETUP
-----
1. Create a Dropbox app at https://www.dropbox.com/developers/apps
     - API:    Scoped access
     - Access: Full Dropbox
2. Permissions tab. Enable BOTH sections:
     Team Scopes:       team_info.read, members.read, team_data.member,
                        team_data.content.read
     Individual Scopes: files.metadata.read
   Submit. Adding a scope does not retroactively grant it to an existing
   token, so generate the token AFTER saving scopes.
3. A Dropbox TEAM ADMIN must complete the OAuth flow. A token generated
   from the App Console button is user-linked and will fail on team calls.
   The token exchange response must contain a team_id field.
4. export DROPBOX_TEAM_TOKEN="sl.xxxxx"
5. pip install dropbox
6. python Discover-DropboxInventory.py

ADMIN SELECTION
---------------
Dropbox returns an empty roles list for regular members and one or more
role objects for admins. Role display names vary by team, so this script
treats any member with a non-empty roles list as an admin candidate and
prefers a full Team admin when one is present.

If detection picks the wrong account, set ADMIN_EMAIL below to force it.
Run with --list-admins to print every admin and role the API reports.
"""

import csv
import os
import sys
import time
from collections import Counter, defaultdict

try:
    import dropbox
    from dropbox import DropboxTeam
    from dropbox.common import PathRoot
    from dropbox.files import FileMetadata, FolderMetadata
except ImportError:
    sys.exit("Missing dependency. Run: pip install dropbox")


# ----------------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------------
TOKEN = os.environ.get("DROPBOX_TEAM_TOKEN")
OUT_MANIFEST = "dropbox_file_manifest.csv"
OUT_SUMMARY = "dropbox_inventory_summary.txt"

# Force a specific admin account for Select-Admin calls. Leave blank to
# auto-detect. Example: "admin@contoso.com"
ADMIN_EMAIL = ""

INCLUDE_TEAM_FOLDERS = True
INCLUDE_MEMBER_FOLDERS = True

# Set to an integer while testing to stop after N namespaces. None = all.
LIMIT_NAMESPACES = None

# Retry/backoff for rate limiting
MAX_RETRIES = 5


# ----------------------------------------------------------------------
# HELPERS
# ----------------------------------------------------------------------
def call_with_retry(fn, *args, **kwargs):
    """Wrap an API call with backoff for 429 rate limiting."""
    for attempt in range(MAX_RETRIES):
        try:
            return fn(*args, **kwargs)
        except dropbox.exceptions.RateLimitError as e:
            wait = getattr(e.error, "retry_after", None) or (2 ** attempt)
            print(f"    rate limited, sleeping {wait}s")
            time.sleep(wait)
        except dropbox.exceptions.ApiError as e:
            print(f"    API error: {e}")
            return None
    print("    gave up after retries")
    return None


def get_roles(member):
    """
    Return a list of role objects for a member.

    members/list_v2 returns TeamMemberInfoV2 with a `roles` list.
    Older members/list returns TeamMemberInfo with a singular `role`.
    Regular members come back with an empty list.
    """
    raw = getattr(member, "roles", None)
    if raw is None:
        raw = getattr(member, "role", None)
    if raw is None:
        return []
    roles = raw if isinstance(raw, (list, tuple)) else [raw]
    return [r for r in roles if r is not None]


def role_label(role):
    """Best-effort display name for a role object."""
    for attr in ("name", "role_id"):
        val = getattr(role, attr, None)
        if isinstance(val, str) and val:
            return val
    # Legacy AdminTier union exposes is_team_admin() instead of a name.
    checker = getattr(role, "is_team_admin", None)
    if callable(checker):
        try:
            return "team_admin" if checker() else "admin"
        except Exception:
            pass
    return str(role)


def is_full_team_admin(role):
    """
    True when the role grants full team admin.

    Dropbox reports this role as "Team admin" in its published sample and
    as "Team" on some tenants. role_id is opaque (pid_dbtmr:AAAA...) so it
    cannot be pattern matched. Other admin roles (User management, Support,
    Billing, Content, Compliance, Reporting, Security) do not start with
    "team" and are excluded.
    """
    checker = getattr(role, "is_team_admin", None)
    if callable(checker):
        try:
            if checker():
                return True
        except Exception:
            pass
    name = getattr(role, "name", None)
    if isinstance(name, str) and name.strip().lower().startswith("team"):
        return True
    return False


def pick_admin(members):
    """
    Choose a team_member_id for Select-Admin calls.

    members is a list of (team_member_id, email, status, roles) tuples.
    Prefers a full Team admin, falls back to any admin role.
    Returns (member_id, email, note) or (None, None, reason).
    """
    admins = [m for m in members if m[3]]
    if not admins:
        return None, None, "no members returned any admin role"

    for member_id, email, status, roles in admins:
        if status != "active":
            continue
        if any(is_full_team_admin(r) for r in roles):
            return member_id, email, "full team admin"

    for member_id, email, status, roles in admins:
        if status != "active":
            continue
        labels = ", ".join(role_label(r) for r in roles)
        return member_id, email, f"partial admin role ({labels})"

    return None, None, "admin accounts found but none are active"


def walk_namespace(client, label, source_type, writer, counters):
    """Recursively list every file in one namespace and write rows."""
    result = call_with_retry(
        client.files_list_folder, "", recursive=True, include_deleted=False
    )
    if result is None:
        return 0

    files_seen = 0
    while True:
        for entry in result.entries:
            if isinstance(entry, FolderMetadata):
                counters["folders"] += 1
                continue
            if not isinstance(entry, FileMetadata):
                continue

            path = entry.path_display or entry.path_lower or ""
            name = entry.name
            ext = os.path.splitext(name)[1].lower().lstrip(".") or "(none)"
            size = entry.size or 0

            writer.writerow({
                "namespace": label,
                "source_type": source_type,
                "path": path,
                "name": name,
                "extension": ext,
                "size_bytes": size,
                "client_modified": entry.client_modified,
                "server_modified": entry.server_modified,
                "content_hash": entry.content_hash or "",
                "path_length": len(path),
            })

            files_seen += 1
            counters["files"] += 1
            counters["bytes"] += size
            counters["by_ext"][ext] += 1
            counters["bytes_by_ext"][ext] += size
            if entry.content_hash:
                counters["hashes"][entry.content_hash].append((path, size))
            if size == 0:
                counters["zero_byte"] += 1
            if len(path) > 400:
                counters["long_paths"].append(path)
            if name != name.strip() or name.endswith("."):
                counters["odd_names"].append(path)
            counters["largest"].append((size, path))

        if not result.has_more:
            break
        result = call_with_retry(client.files_list_folder_continue, result.cursor)
        if result is None:
            break

    return files_seen


def human(n):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(n) < 1024.0:
            return f"{n:,.2f} {unit}"
        n /= 1024.0
    return f"{n:,.2f} PB"


# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------
def main():
    if not TOKEN:
        sys.exit("Set DROPBOX_TEAM_TOKEN before running.")

    list_admins_only = "--list-admins" in sys.argv

    team = DropboxTeam(TOKEN)

    info = call_with_retry(team.team_get_info)
    if info:
        print(f"Team: {info.name}  |  licensed users: {info.num_licensed_users}")

    # Enumerate members and capture their roles.
    page = call_with_retry(team.team_members_list_v2)
    members = []
    while page:
        for m in page.members:
            profile = m.profile
            members.append((
                profile.team_member_id,
                profile.email,
                profile.status._tag,
                get_roles(m),
            ))
        if not page.has_more:
            break
        page = call_with_retry(team.team_members_list_v2_continue, page.cursor)

    admin_rows = [m for m in members if m[3]]

    if list_admins_only:
        print(f"\nMembers: {len(members)}  |  with admin roles: {len(admin_rows)}\n")
        for member_id, email, status, roles in admin_rows:
            labels = ", ".join(role_label(r) for r in roles)
            flag = "  <- full team admin" if any(
                is_full_team_admin(r) for r in roles
            ) else ""
            print(f"  {email:<45} {status:<10} {labels}{flag}")
        if not admin_rows:
            print("  none reported. Confirm the token has members.read scope.")
        return

    # Resolve the admin used for Select-Admin calls.
    if ADMIN_EMAIL:
        match = [m for m in members if m[1].lower() == ADMIN_EMAIL.lower()]
        if not match:
            sys.exit(f"ADMIN_EMAIL {ADMIN_EMAIL} not found in the team member list.")
        admin_id, admin_email = match[0][0], match[0][1]
        note = "forced via ADMIN_EMAIL"
    else:
        admin_id, admin_email, note = pick_admin(members)

    if admin_id is None:
        print(f"\nCould not select an admin: {note}")
        print("Run with --list-admins to see what the API reports, or set")
        print("ADMIN_EMAIL near the top of this script to force an account.")
        sys.exit(1)

    print(f"Members discovered: {len(members)}  |  admins: {len(admin_rows)}")
    print(f"Acting admin: {admin_email} ({note})")

    counters = {
        "files": 0, "folders": 0, "bytes": 0, "zero_byte": 0,
        "by_ext": Counter(), "bytes_by_ext": Counter(),
        "hashes": defaultdict(list),
        "long_paths": [], "odd_names": [], "largest": [],
    }

    fields = [
        "namespace", "source_type", "path", "name", "extension",
        "size_bytes", "client_modified", "server_modified",
        "content_hash", "path_length",
    ]

    processed = 0
    with open(OUT_MANIFEST, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()

        # --- Team folders, walked as admin against each namespace root ---
        if INCLUDE_TEAM_FOLDERS:
            tf = call_with_retry(team.team_team_folder_list)
            while tf:
                for entry in tf.team_folders:
                    if LIMIT_NAMESPACES and processed >= LIMIT_NAMESPACES:
                        break
                    ns = entry.team_folder_id
                    label = entry.name
                    print(f"[team folder] {label}")
                    client = team.as_admin(admin_id).with_path_root(
                        PathRoot.namespace_id(ns)
                    )
                    n = walk_namespace(client, label, "team_folder", writer, counters)
                    print(f"    {n:,} files")
                    processed += 1
                if not tf.has_more:
                    break
                tf = call_with_retry(team.team_team_folder_list_continue, tf.cursor)

        # --- Member home folders, walked as each user ---
        if INCLUDE_MEMBER_FOLDERS:
            for member_id, email, status, _roles in members:
                if LIMIT_NAMESPACES and processed >= LIMIT_NAMESPACES:
                    break
                if status not in ("active", "suspended"):
                    continue
                print(f"[member] {email} ({status})")
                client = team.as_user(member_id)
                n = walk_namespace(client, email, f"member_{status}", writer, counters)
                print(f"    {n:,} files")
                processed += 1

    # ------------------------------------------------------------------
    # SUMMARY
    # ------------------------------------------------------------------
    dupes = {h: v for h, v in counters["hashes"].items() if len(v) > 1}
    dupe_files = sum(len(v) - 1 for v in dupes.values())
    dupe_bytes = sum(v[0][1] * (len(v) - 1) for v in dupes.values())
    counters["largest"].sort(reverse=True)

    lines = []
    add = lines.append
    add("DROPBOX INVENTORY SUMMARY")
    add("=" * 60)
    add(f"Namespaces walked        : {processed:,}")
    add(f"Total files              : {counters['files']:,}")
    add(f"Total folders            : {counters['folders']:,}")
    add(f"Total items (files+dirs) : {counters['files'] + counters['folders']:,}")
    add(f"Total size               : {human(counters['bytes'])}")
    add("")
    add("GOOGLE SHARED DRIVE PLANNING")
    add("-" * 60)
    add("Shared drive item cap is 500,000 items including folders and trash.")
    add(f"Current item count       : {counters['files'] + counters['folders']:,}")
    add("Per-user upload cap is 750 GB per 24 hours.")
    est_days = counters["bytes"] / (750 * 1024 ** 3) if counters["bytes"] else 0
    add(f"Minimum transfer days at 750 GB/day/account: {est_days:.1f}")
    add("")
    add("CLEANUP CANDIDATES")
    add("-" * 60)
    add(f"Zero-byte files          : {counters['zero_byte']:,}")
    add(f"Duplicate files          : {dupe_files:,}  ({human(dupe_bytes)} reclaimable)")
    add(f"Paths over 400 chars     : {len(counters['long_paths']):,}")
    add(f"Names w/ trailing space or dot : {len(counters['odd_names']):,}")
    add("")
    add("TOP 25 EXTENSIONS BY FILE COUNT")
    add("-" * 60)
    for ext, cnt in counters["by_ext"].most_common(25):
        add(f"  {ext:<12} {cnt:>10,}   {human(counters['bytes_by_ext'][ext]):>14}")
    add("")
    add("TOP 25 LARGEST FILES")
    add("-" * 60)
    for size, path in counters["largest"][:25]:
        add(f"  {human(size):>12}  {path}")

    text = "\n".join(lines)
    with open(OUT_SUMMARY, "w", encoding="utf-8") as fh:
        fh.write(text)

    print()
    print(text)
    print()
    print(f"Manifest written to {OUT_MANIFEST}")
    print(f"Summary written to  {OUT_SUMMARY}")


if __name__ == "__main__":
    main()
