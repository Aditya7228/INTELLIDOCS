# IntelliDocs Offline Capability Audit

Generated: 2026-10-07T01:49:32

## Purpose
This is a code-level dependency audit. It does not claim that the entire application was tested under complete network isolation.

## Classification guidance

- FULL OFFLINE: functionality is designed around local resources and has no required network dependency.
- MOSTLY OFFLINE: core operation is local, but optional/external functionality may use the network.
- NETWORK REQUIRED: the functionality depends on an external service or network connection.
- OPTIONAL NETWORK: local operation exists, while a network enhancement such as email may be available.
- UNKNOWN: code inspection alone is insufficient.

## Detected Potential Network/Remote Dependencies

| Type | File | Lines |
|---|---|---:|
| URL literals | `backend\config.py` | 21, 21, 21, 21, 21 |
| Model download/load | `backend\api\documents.py` | 199, 200, 223 |
| SMTP | `backend\api\support.py` | 2, 104, 104 |
| HTTP libraries | `frontend\app.js` | 4189, 4194 |
| Browser fetch | `frontend\app.js` | 254, 259, 269 |
| Model download/load | `frontend\app.js` | 293, 777, 806, 808, 932 |
| HTTP libraries | `frontend\index.html` | 917, 1110, 1114, 1129 |
| Model download/load | `frontend\index.html` | 468, 468, 1003, 1014, 1662 |

## Runtime verification still required

Complete network isolation testing should be performed separately before making a claim of full offline operation.

Suggested local checks:

```powershell
python -m pytest -q
python -m compileall backend
git diff --check
```
