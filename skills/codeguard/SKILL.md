---
name: codeguard
description: "Security-aware code generation — teaches the agent CodeGuard rules to write secure code by default"
---

# CodeGuard: Secure Code Generation Rules

You MUST follow these security rules when writing code. Code that violates these
rules will be **blocked** by the DefenseClaw CodeGuard scanner before it reaches
disk. Write it correctly the first time.

---

## Credentials — all languages

### CG-CRED-001: Never hardcode API keys or secrets

Assigning API keys, secret keys, access tokens, or private keys directly in
source code exposes them in version control and build artifacts.

```python
# BAD — blocked
api_key = "sk-proj-abcdefghij1234567890"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GOOD
import os
api_key = os.environ["API_KEY"]
```

```javascript
// BAD — blocked
const accessToken = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

// GOOD
const accessToken = process.env.ACCESS_TOKEN;
```

### CG-CRED-002: Never include AWS access key IDs

AWS keys that start with `AKIA` followed by 16 alphanumeric characters are
detected regardless of context.

```python
# BAD — blocked
aws_key = "AKIAIOSFODNN7EXAMPLE"

# GOOD
import boto3
session = boto3.Session()  # uses ~/.aws/credentials or IAM role
```

### CG-CRED-003: Never embed private keys (CRITICAL)

PEM-encoded private keys (`-----BEGIN RSA PRIVATE KEY-----` and variants) are
the highest severity finding. They grant full authentication as the key holder.

```python
# BAD — blocked (CRITICAL severity)
KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""

# GOOD — load from file or secrets manager at runtime
with open("/etc/ssl/private/server.key") as f:
    key = f.read()
```

---

## Command Execution — Python, JavaScript, TypeScript, Ruby, PHP

### CG-EXEC-001: Never use os.system(), eval(), exec(), or child_process.exec()

These functions pass strings to a shell interpreter, enabling command injection
when any part of the string comes from user input or external data.

```python
# BAD — blocked
import os
os.system(f"grep {user_input} /var/log/app.log")

# GOOD
import subprocess
subprocess.run(["grep", user_input, "/var/log/app.log"], check=True)
```

```javascript
// BAD — blocked
const { exec } = require("child_process");
exec(`ls ${userDir}`);

// GOOD
const { execFile } = require("child_process");
execFile("ls", [userDir], callback);
```

```python
# BAD — blocked
result = eval(user_expression)

# GOOD
import ast
result = ast.literal_eval(user_expression)
```

### CG-EXEC-002: Never use shell=True in subprocess (Python)

Even with `subprocess`, passing `shell=True` re-introduces shell injection risk.

```python
# BAD — blocked
subprocess.call(f"convert {infile} {outfile}", shell=True)

# GOOD
subprocess.run(["convert", infile, outfile], check=True)
```

---

## SQL — Python, JavaScript, TypeScript, Ruby, PHP, Java

### CG-SQL-001: Never format strings into SQL queries

String interpolation in SQL enables SQL injection. Always use parameterized
queries with bind variables.

```python
# BAD — blocked
cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)

# GOOD
cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
```

```javascript
// BAD — blocked
db.query(`SELECT * FROM users WHERE id = ${userId}`);

// GOOD
db.query("SELECT * FROM users WHERE id = ?", [userId]);
```

```java
// BAD — blocked
stmt.execute("SELECT * FROM users WHERE id = " + userId);

// GOOD
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setInt(1, userId);
```

---

## Deserialization — Python

### CG-DESER-001: Never use pickle or yaml.load on untrusted data

`pickle.load`/`pickle.loads` can execute arbitrary code during deserialization.
`yaml.load` without a safe Loader is equally dangerous.

```python
# BAD — blocked
import pickle
obj = pickle.loads(request.data)

import yaml
config = yaml.load(user_yaml)

# GOOD
import json
obj = json.loads(request.data)

import yaml
config = yaml.safe_load(user_yaml)
```

---

## Cryptography — Python, JavaScript, TypeScript, Java, Go, Ruby

### CG-CRYPTO-001: Never use MD5 or SHA1

MD5 and SHA1 are cryptographically broken. Use SHA-256 or stronger.

```python
# BAD — blocked
import hashlib
h = hashlib.md5(data)
h = hashlib.sha1(data)

# GOOD
import hashlib
h = hashlib.sha256(data)
```

```javascript
// BAD — blocked
crypto.createHash("md5").update(data);
crypto.createHash("sha1").update(data);

// GOOD
crypto.createHash("sha256").update(data);
```

---

## Network — Python, JavaScript, TypeScript, Go

### CG-NET-001: Validate outbound URLs

HTTP requests to URLs constructed from variables can enable SSRF (Server-Side
Request Forgery). Validate and allowlist target URLs.

```python
# CAUTION — flagged for review
response = requests.get(user_url)

# GOOD — validate against allowlist
ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
parsed = urllib.parse.urlparse(user_url)
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("URL not allowed")
response = requests.get(user_url)
```

---

## Path Safety — all languages

### CG-PATH-001: Never construct paths with ../

Path traversal sequences (`../`) allow escaping intended directories to read or
write arbitrary files.

```python
# BAD — blocked
path = os.path.join(upload_dir, "../../etc/passwd")

# GOOD — canonicalize and validate
real = os.path.realpath(os.path.join(upload_dir, filename))
if not real.startswith(os.path.realpath(upload_dir)):
    raise ValueError("path traversal detected")
```

---

## Quick Reference

| Rule | Severity | Languages | Instead of | Use |
|------|----------|-----------|-----------|-----|
| CG-CRED-001 | HIGH | all | `api_key = "sk-..."` | `os.environ["API_KEY"]` |
| CG-CRED-002 | HIGH | all | `AKIA...` in source | IAM roles / `~/.aws/credentials` |
| CG-CRED-003 | CRITICAL | all | `-----BEGIN PRIVATE KEY-----` | Secrets manager / file at runtime |
| CG-EXEC-001 | HIGH | py,js,ts,rb,php | `os.system()`, `eval()` | `subprocess.run([...])` |
| CG-EXEC-002 | MEDIUM | py | `shell=True` | `subprocess.run([...])` |
| CG-SQL-001 | HIGH | py,js,ts,rb,php,java | f-strings in SQL | Parameterized queries |
| CG-DESER-001 | HIGH | py | `pickle.loads()` | `json.loads()` |
| CG-CRYPTO-001 | MEDIUM | py,js,ts,java,go,rb | `hashlib.md5()` | `hashlib.sha256()` |
| CG-NET-001 | MEDIUM | py,js,ts,go | `requests.get(var)` | URL allowlist validation |
| CG-PATH-001 | MEDIUM | all | `../../etc/passwd` | `os.path.realpath()` + prefix check |
