# Dropbox Inventory Discovery

A single Python script that walks an entire Dropbox Business team through the Dropbox API and produces an exact, file-level inventory for migration scoping.

Built for pre-sales discovery on Dropbox migration projects, where you need real numbers before you quote the work and you do not want to connect a third-party migration tool to a client tenant that has not signed anything yet.

## What it produces

**`dropbox_file_manifest.csv`** - one row per file across every team folder and every member home folder:

| Column | Description |
|---|---|
| `namespace` | Team folder name, or member email |
| `source_type` | `team_folder`, `member_active`, or `member_suspended` |
| `path` | Full display path |
| `name` | File name |
| `extension` | Lowercased extension, `(none)` if absent |
| `size_bytes` | File size |
| `client_modified` | Timestamp from the client |
| `server_modified` | Timestamp from Dropbox |
| `content_hash` | Dropbox content hash, used for duplicate detection |
| `path_length` | Character count, for spotting path-length risks |

**`dropbox_inventory_summary.txt`** - a scoping summary covering total files, folders, combined item count, total size, Google Shared Drive planning figures, duplicate and zero-byte counts, reclaimable space, long paths, problem file names, the top 25 extensions by count, and the top 25 largest files.

## Why bother

The Dropbox admin console team storage report gives you folder paths, sizes, owners, and per-folder file counts. That is enough to price a migration tool but not enough to price the labor. It tells you nothing about duplicates, zero-byte files, extension mix, or path-length problems, and those are what turn a clean cutover into a support queue.

This script gets you that detail using credentials the client already controls, with no vendor connector and no data leaving the tenant.

## Requirements

- Python 3.9 or newer
- The `dropbox` Python SDK
- A Dropbox Business team
- A Dropbox **team admin** account to authorize the app

## Part 1: Create the Dropbox app

1. Go to <https://www.dropbox.com/developers/apps> and select **Create app**.
2. Choose:
   - **Scoped access**
   - **Full Dropbox** (not App folder)
3. Name it something identifiable, for example `Inventory-Discovery`.
4. Create the app. You land on the **Settings** tab. Note the **App key** and **App secret**, you will need both.

## Part 2: Set permissions

Open the **Permissions** tab. There are two separate sections and you need boxes checked in both. Missing the team section is the most common failure, and it produces a token that looks valid but fails on every team call.

**Team Scopes**

| Scope | Why |
|---|---|
| `team_info.read` | Read team name and licensed user count |
| `members.read` | Enumerate members and identify an admin |
| `team_data.member` | Required for any Select-User or Select-Admin call |
| `team_data.content.read` | Read team-owned folder content as admin |

**Individual Scopes**

| Scope | Why |
|---|---|
| `files.metadata.read` | Required by `files/list_folder` |

Select **Submit** at the bottom of the page. Changes do not save otherwise.

> **Important:** Adding a scope does not retroactively grant it to an existing token. Always generate the token after saving scopes. If you add a scope later, generate a fresh token.

## Part 3: Get a team-linked token

The **Generate access token** button on the Settings tab produces a token linked to *your* account. Team endpoints will reject it with:

```
BadInputError: 'This token is not associated with a team' error_type:USER_AUTH_NOT_ALLOWED
```

You need a **team-linked** token, which means a team admin has to complete the OAuth flow. Only team admins can connect team-linked apps.

**Step 1.** In a browser signed in as a team admin of the target tenant, open:

```
https://www.dropbox.com/oauth2/authorize?client_id=YOUR_APP_KEY&response_type=code&token_access_type=offline
```

Approve the request and copy the authorization code.

**Step 2.** Exchange the code for a token:

```bash
curl -X POST https://api.dropboxapi.com/oauth2/token \
  -d code=PASTE_CODE_HERE \
  -d grant_type=authorization_code \
  -u YOUR_APP_KEY:YOUR_APP_SECRET
```

**Step 3.** Verify the response contains a `team_id` field. That field is your proof the token is team-linked. If it is missing, the app is still user-linked and the scan will fail.

The response also includes a `refresh_token`. Keep it. Access tokens are short-lived and a full tenant walk can outlast one.

## Part 4: Install

Do not install into system Python. On macOS with Homebrew this is blocked by PEP 668 anyway. Use a virtual environment:

```bash
python3 -m venv ~/dropbox-discovery
source ~/dropbox-discovery/bin/activate
python -m pip install --upgrade pip
python -m pip install dropbox
```

Your prompt shows `(dropbox-discovery)` while active. Run `deactivate` when finished. Next session, re-run only the `source` line.

Never run `sudo pip install`. It writes root-owned files into your Python tree and causes permission problems later.

## Part 5: Run it

Export the token, then confirm admin detection before committing to a full walk:

```bash
export DROPBOX_TEAM_TOKEN="sl.xxxxx"
python Discover-DropboxInventory.py --list-admins
```

That prints every account carrying an admin role, the exact role names the API reports, and flags which one qualifies as a full team admin. Expected output looks like:

```
Team: Contoso  |  licensed users: 55

Members: 55  |  with admin roles: 3

  admin@contoso.com            active     Team  <- full team admin
  helpdesk@contoso.com         active     Support admin
  billing@contoso.com          active     Billing admin
```

Next, smoke test against a couple of namespaces. Open the script and set:

```python
LIMIT_NAMESPACES = 2
```

Run it, confirm the manifest looks right, then set it back to `None` and run the full scan:

```bash
python Discover-DropboxInventory.py
```

## Configuration

All settings live at the top of the script.

| Setting | Default | Purpose |
|---|---|---|
| `ADMIN_EMAIL` | `""` | Force a specific admin account. Leave blank to auto-detect. |
| `INCLUDE_TEAM_FOLDERS` | `True` | Walk team folders |
| `INCLUDE_MEMBER_FOLDERS` | `True` | Walk member home folders |
| `LIMIT_NAMESPACES` | `None` | Stop after N namespaces. Use an integer for testing. |
| `MAX_RETRIES` | `5` | Backoff attempts on rate limiting |
| `OUT_MANIFEST` | `dropbox_file_manifest.csv` | Manifest output path |
| `OUT_SUMMARY` | `dropbox_inventory_summary.txt` | Summary output path |

## How admin detection works

Dropbox returns an empty `roles` array for regular members and populated entries only for admins. Role display names vary between tenants. Dropbox documentation shows the full admin role as `Team admin`, but live tenants frequently report it as just `Team`. The `role_id` is an opaque value such as `pid_dbtmr:AAAAAFMcx6E0tax39` and cannot be pattern matched.

The script therefore treats any member with a non-empty `roles` list as an admin candidate, then prefers a role whose display name starts with `Team`, since Select-Admin requires a full team administrator rather than a Support, Billing, or User management admin. Suspended accounts are skipped.

If detection picks the wrong account, run `--list-admins` and set `ADMIN_EMAIL` to override.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `This token is not associated with a team` | Token is user-linked | Redo Part 3 as a team admin, confirm `team_id` in the response |
| `does not have the required scope 'files.metadata.read'` | Scope missing, or token predates the scope | Enable the scope, submit, generate a new token |
| `'TeamMemberInfoV2' object has no attribute 'role'` | Old script version | Update to current release |
| `Could not select an admin` | Authorizing account lacks a full admin role | Run `--list-admins`, then set `ADMIN_EMAIL` |
| `You must be a team administrator` | Authorized as a regular member | Reauthorize using a team admin account |
| Scan dies partway through a large tenant | Access token expired | Use the refresh token to mint a new one and rerun |
| `error: externally-managed-environment` | Installing into system Python | Use a virtual environment, see Part 4 |

## Known limitations

- **No refresh-token handling.** The script takes a static token. Large tenants can outrun the token lifetime and the scan will stop.
- **No resume.** A failed run restarts from the beginning.
- **Metadata only.** File contents are never read or downloaded.
- **Shared folder double counting.** A folder mounted by several members is counted once per member namespace it appears in. Deduplicate on `content_hash` when a unique count is needed.
- **Rate limiting.** Backoff is handled, but a large tenant walk still takes time.

## Useful analysis

Once the manifest exists, ordinary tooling answers most scoping questions:

```bash
# Total files
wc -l < dropbox_file_manifest.csv

# Largest namespaces by file count
awk -F, 'NR>1 {print $1}' dropbox_file_manifest.csv | sort | uniq -c | sort -rn | head -20
```

```python
import pandas as pd
df = pd.read_csv("dropbox_file_manifest.csv")

# Size by namespace, in GB
print(df.groupby("namespace")["size_bytes"].sum().div(1024**3).sort_values(ascending=False).head(20))

# Files untouched in over three years
old = df[pd.to_datetime(df["server_modified"]) < "2022-09-18"]
print(f"{len(old):,} stale files, {old['size_bytes'].sum()/1024**3:,.1f} GB")
```

## Security

- Team tokens grant broad access to team data. Never commit one to source control.
- Use an environment variable, never a hardcoded value.
- Revoke the app in the Dropbox admin console when discovery is finished.
- The script reads metadata only. No file contents are downloaded.
- Both output files contain full file paths and can be sensitive. Treat them as client confidential.

## Reference

- [Dropbox Business API overview](https://docs.dropboxapi.com/dropbox-api/api-reference/business-endpoints/overview)
- [Authentication types](https://www.dropbox.com/developers/reference/auth-types)
- [Team Files guide](https://docs.dropboxapi.com/dropbox-api/docs/team-files)
- [Shared drive limits in Google Drive](https://support.google.com/a/users/answer/7338880)
- [Google Drive large migration best practices](https://knowledge.workspace.google.com/admin/getting-started/google-drive-large-migration-best-practices)

## License

MIT
