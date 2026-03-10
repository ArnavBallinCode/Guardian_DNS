# API examples

## 0) Assess via Ollama + internet context

```bash
curl -s -X POST http://127.0.0.1:8000/decision/assess \
  -H 'Content-Type: application/json' \
  -d '{
    "domain":"example-risky.com",
    "category_hint":"unknown",
    "evidence_urls":["https://example-risky.com"],
    "skip_context_fetch": true
  }'
```

## 1) AI evaluates domain

```bash
curl -s -X POST http://127.0.0.1:8000/decision/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example-risky.com","category":"adult-content","p_risk":0.94}'
```

## 2) Adults vote on AI judgment

```bash
curl -s -X POST http://127.0.0.1:8000/review/vote \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example-risky.com","reviewer_id":"reviewer-1","agree":true,"proof":"verification-ticket-001"}'
```

## 3) Parent dashboard (aggregate only)

```bash
curl -s 'http://127.0.0.1:8000/parent/summary?days=7'
```

## 4) DNS export

```bash
curl -s http://127.0.0.1:8000/export/domains.txt
curl -s http://127.0.0.1:8000/export/rpz
```
