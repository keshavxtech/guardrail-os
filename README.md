# Guardrail OS

A zero-dependency hackathon MVP for controlling AI-agent tool actions with deterministic policies and human approval.

## Current stages

### Stage 1 — Product foundation
- Enterprise security dashboard UI
- Overview, Agent Sessions, Policies, Approvals, Tools, Flight Recorder, Audit Log, Settings
- Local browser persistence
- Inter for normal UI text; IBM Plex Mono for technical data

### Stage 2 — Deterministic Policy Engine
Every simulated tool action is evaluated before execution:
- `ALLOW`
- `APPROVE`
- `BLOCK`

Included controls: refund thresholds, PII export, destructive database actions, and bulk communication rate review.

### Stage 3 — Human Approval Workflow
- Approval requests carry policy, risk, session, parameters and expiry metadata
- Explicit Approve / Reject decisions
- Five-minute approval expiry for new requests
- Reviewer decision history
- Approval decisions are written to the action/audit stream
- Local persistence across refreshes

### QA / hardening checkpoint
- Expired approval requests are pruned from the pending queue instead of remaining as actionable items
- Approval release re-checks the current policy state before execution
- Session pause/resume is a real control, not a placeholder toast
- Tool adapters for customer lookup, invoice fetch, and pod restart are covered by an explicit safe-operation policy
- Invalid refund/email payloads are rejected before policy execution
- Audit records are no longer truncated in a way that breaks hash-chain verification
- Corrupt local state is handled safely instead of crashing the application
- Runtime/security regression tests cover validation, fail-closed behavior, PII/secret redaction, and audit tamper detection

### Stage 7 — QA and cleanup
- Full regression suite runs through `npm test`
- Tool registry UI matches the seven local adapters
- Safe-operation tools are explicitly covered by policy
- Stale placeholder controls removed from the MVP UI
- Approval, pause/resume, validation, and audit flows were regression-tested

## Run

```bash
npm test
npm run serve
```

Open `http://localhost:4173`.

No API keys, external services, database, or paid services are required.


### Stage 4 — Flight Recorder
- Every intercepted action creates a replayable local trace
- Step-by-step session replay and JSON export

### Stage 5 — Tool Boundary / Interception Layer
- Explicit local tool registry and adapters
- `GuardrailRuntime.intercept()` is the execution gate
- Allowed actions execute only through registered adapters
- Approval actions remain held until a human decision
- Blocked actions never reach a tool adapter
- Tool failures fail closed and are recorded

### Stage 6 — Security Hardening / Audit Integrity
- Input validation and tool allowlist
- 8 KB payload ceiling
- Prototype-pollution key rejection
- PII redaction before trace/audit persistence
- Hash-chained audit records using Web Crypto SHA-256 when available
- Audit-chain verification control in Settings
- Default-deny behavior on unknown tools and policy-engine errors
