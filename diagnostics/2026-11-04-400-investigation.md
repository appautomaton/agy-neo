# Antigravity CLI 400 investigation

## Finding

The recorded failure is not a permanently invalid request body or a destroyed
conversation. Google rejected one request with `400 INVALID_ARGUMENT` and later
accepted the same outbound body, including all saved thought signatures. Only
the normal, randomly generated `requestId` changed.

This establishes inconsistent upstream handling of this request. It does not
identify Google's internal validation or deployment failure. No client-side
signature-removal patch is justified by the evidence collected here.

## Matched requests

Both requests used CPA v8.0.54, the same Antigravity credential, model
`gemini-4-argon-high`, and
`https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse`.

| Observation | Failed request | Successful request |
| --- | --- | --- |
| Request time, local | 2026-11-04 22:32:43 | 2026-11-04 23:02:45 |
| Local request log ID | `247d62f4` | `20ec9f67` |
| Final HTTP status | 400 | 200 |
| Stream completion | Rejected before generation | Completed with `STOP` |

The raw bodies are byte-identical after replacing only the top-level
`requestId` UUID with a fixed UUID. Their normalized SHA-256 is:

`97968e621cb3f7585577b9c8ee9dc6254d02e266e0231588a9d2354ccfb617de`

The machine-readable comparison is in `2026-11-04-400-evidence.json`.
Private source logs and replay payloads remain in `/tmp`; they are not included
in this report.

## Conversation recovery

Original conversation: `<conversation-id>`.
Original trajectory: `<trajectory-id>`.

The original database was left unchanged. A diagnostic fork retained all six
original steps, including the original error, while replacing conversation and
trajectory identifiers to isolate execution:

`<fork-conversation-id>`

The fork completed a new reply and a subsequent `pwd` tool call plus final reply
through native OAuth. Database inspection found no new error steps: the only
error remains original step 5. No signatures or conversation content were
removed to obtain this recovery.

Print mode nevertheless reported `status: ERROR` and repeated the old 400 while
also returning the successful new response. Its cumulative error status must not
be used alone to judge the new turn.

Global settings were also observed with `modelProvider: gemini` again. This
session-only override was verified to select native OAuth without changing the
shared provider preference:

```sh
agy --settings '{"modelProvider":""}' --conversation=<fork-conversation-id>
```

Temporary CPA request-body logging was restored to its initial disabled state.
No installed binary, production source, or original conversation was patched.
