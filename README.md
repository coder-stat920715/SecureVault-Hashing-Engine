# SecureVault-Hashing-Engine

Spring Boot 3.3 (Java 17/21) showcase of six real-world hashing use cases in one domain: an
**Enterprise Secure Document & Audit Vault**.

| # | Use case | Mechanism | Package / key class |
|---|----------|-----------|---------------------|
| 1 | Password hashing + JWT | Argon2id or BCrypt (random salt, configurable cost), JWT signed with HMAC-SHA256 | `auth` / `PasswordEncoderConfig`, `JwtService` |
| 2 | Transfer integrity | Streaming SHA-256 via `DigestInputStream`; download re-verifies, 422 on mismatch | `integrity` / `ChecksumService`, `DocumentService` |
| 3 | Deduplication | Content-addressable store; in-memory hash set + unique-indexed hash table | `integrity` / `DeduplicationService`, `BlobStorageService` |
| 4 | Webhook authentication | `javax.crypto.Mac` HMAC-SHA256, constant-time compare, 401 on failure | `crypto` / `HmacSignatureVerifier` |
| 5 | Tamper-evident audit log | `SHA256(prev \| timestamp \| action \| payloadHash)` hash chain | `audit` / `AuditLogService` |
| 6 | Consistent hashing | `TreeMap` ring, 100 virtual nodes/node, MD5 or Murmur3 | `cluster` / `ConsistentHashRing` |

Every key hashing method carries a JavaDoc explaining *why* that algorithm was chosen.

## Run

```bash
mvn verify                      # compiles + runs unit and integration tests
mvn spring-boot:run             # http://localhost:8080  (file-based H2 in ./data)
# PostgreSQL instead of H2:
SPRING_PROFILES_ACTIVE=postgres DB_URL=jdbc:postgresql://localhost:5432/vault DB_USER=vault DB_PASSWORD=vault mvn spring-boot:run
```

Configuration lives in `src/main/resources/application.yml` (prefix `vault.*`). **Set `VAULT_JWT_SECRET`
(>= 32 bytes) and `VAULT_WEBHOOK_SECRET` outside development.** Switch `vault.password.algorithm` to `BCRYPT`
to use BCrypt; raise `vault.cluster.virtual-nodes` or set `hash-function: MURMUR3` to experiment with the ring.

## End-to-end walkthrough (cURL)

An equivalent `requests.http` file is included.

```bash
H=http://localhost:8080

# 1. Register + login (JWT, HS256)
curl -s -X POST $H/api/auth/register -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"CorrectHorse-Battery9"}'
TOKEN=$(curl -s -X POST $H/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"CorrectHorse-Battery9"}' | sed -E 's/.*"token":"([^"]+)".*/\1/')
AUTH="Authorization: Bearer $TOKEN"

# 2. Upload with a client-side checksum (422 if the bytes were corrupted in transit), then download
echo "Hello, vault!" > hello.txt
SHA=$(sha256sum hello.txt | cut -d' ' -f1)            # macOS: shasum -a 256
curl -s -X POST $H/api/documents -H "$AUTH" -F file=@hello.txt -F expectedSha256=$SHA
ID=<id from the response>
curl -i $H/api/documents/download/$ID -H "$AUTH"         # X-Content-SHA256 header is returned

# 3. Deduplication: upload the same bytes again -> "deduplicated": true, same storagePath
curl -s -X POST $H/api/documents -H "$AUTH" -F file=@hello.txt
curl -s $H/api/documents/stats -H "$AUTH"                 # bytesSaved > 0

# 4. Webhook: sign the exact raw body with the shared secret
BODY='{"event":"document.shared","id":"42"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac 'whsec_dev_only_change_me' -hex | sed 's/^.* //')
curl -i -X POST $H/api/webhooks/partner-event -H 'Content-Type: application/json' \
  -H "X-Vault-Signature: sha256=$SIG" -d "$BODY"                        # 202
curl -i -X POST $H/api/webhooks/partner-event -H 'Content-Type: application/json' \
  -H "X-Vault-Signature: sha256=$SIG" -d '{"event":"document.shared","id":"43"}'   # 401 (tampered)
curl -i -X POST $H/api/webhooks/partner-event -H 'Content-Type: application/json' -d "$BODY"   # 401 (unsigned)

# 5. Audit chain
curl -s $H/api/audit/verify -H "$AUTH"                    # {"intact":true,...}
curl -s "$H/api/audit/logs?limit=5" -H "$AUTH"

# 6. Consistent hashing
curl -s $H/api/cluster/route-document/$ID -H "$AUTH"
curl -s "$H/api/cluster/node-distribution?sampleSize=20000" -H "$AUTH"
curl -s -X POST $H/api/cluster/nodes -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"id":"worker-d","address":"10.0.0.4:9000"}'        # ~25% of keys move vs ~75% with hash % N
curl -s -X DELETE $H/api/cluster/nodes/worker-d -H "$AUTH"
```

## Tamper demos

**Corrupt a stored file (use case 2).** Append a byte to the blob under `data/storage/ab/cd/<sha256>` and download again:
the response is `422 Unprocessable Entity` and an `ACCESS` event with `download-rejected` is chained into the audit log.

**Edit the audit log (use case 5).** Start with `VAULT_H2_CONSOLE=true`, open `http://localhost:8080/h2-console`
(JDBC URL `jdbc:h2:file:./data/vaultdb`, user `sa`, empty password) and run
`UPDATE audit_log SET payload_hash = REPEAT('f', 64) WHERE id = 1;`.
`GET /api/audit/verify` now returns `intact: false` with the first broken block id. Deleting a middle row is detected too.

## Design notes and hardening checklist

* **Audit ledger**: the repository is append-only (no update/delete methods), the entity is `@Immutable`, and a unique
  index on `previous_event_hash` prevents forks. A hash chain cannot detect deletion of the *newest* blocks or a full
  re-chain by someone with DB write access: publish `headHash` from `/api/audit/verify` to storage outside the DB admin's control.
* **Event details**: only `SHA-256(payload)` is stored per block, not the payload, so the ledger proves a payload existed
  and was unchanged without duplicating (potentially sensitive) data.
* **Dedup race handling**: striped per-hash locks inside one JVM + the unique DB index as arbiter (one retry) for multi-instance setups.
* **PostgreSQL hash index** (optional, equality lookups on the dedup table; hash indexes cannot be unique, keep the unique B-tree too):
  `CREATE INDEX CONCURRENTLY idx_blob_content_hash_hash ON stored_blobs USING HASH (content_hash);`
* **Cross-user deduplication** leaks whether a file already exists (`deduplicated` flag). Deduplicate per tenant if that matters.
* **Webhook replay**: HMAC proves authenticity and integrity, not freshness. For replay protection also sign a timestamp
  header and reject requests older than a few minutes.
* **Not included**: login rate limiting/lockout, refresh tokens, `ROLE_ADMIN` provisioning (an admin bypasses ownership checks;
  set `roles` in `vault_users` manually), and admin-only protection of the cluster mutation endpoints.
* BCrypt only uses the first 72 bytes of a password, so the API caps passwords at 72 characters.
