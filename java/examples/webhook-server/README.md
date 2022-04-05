# Java webhook server example

A http server than can receive and verify signed TrueLayer webhooks.

## Run

Run the server.

```sh
../../gradlew run
```

Send a valid webhook that was signed for path `/hook/d7a2c49d-110a-4ed2-a07d-8fdb3ea6424b`.

```sh
curl -iX POST -H "Content-Type: application/json" \
    -H "X-Tl-Webhook-Timestamp: 2022-03-11T14:00:33Z" \
    -H "Tl-Signature: eyJhbGciOiJFUzUxMiIsImtpZCI6IjFmYzBlNTlmLWIzMzUtNDdjYS05OWE5LTczNzQ5NTc1NmE1OCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGVhZGVycyI6IngtdGwtd2ViaG9vay10aW1lc3RhbXAiLCJqa3UiOiJodHRwczovL3dlYmhvb2tzLnRydWVsYXllci5jb20vLndlbGwta25vd24vandrcyJ9..AE_QsBRhnsMkcRzd42wvY1e2HruUhkOgjuZKktGH_WmbD7rBzoaEHUuF36IxyyvCbLajd3MBExNmzjbrOQsGaspwAI5DcGVMFLKUhB7ZzUlTP9up3eNUrdwWyyfBWDQb-qmEuLnrhFDJvgCXEqlV5OLrt-O7LaRAJ4f9KHsZLQ_j2vPC" \
    -d "{\"event_type\":\"payout_settled\",\"event_schema_version\":1,\"event_id\":\"8fb9fb4e-bb2b-400b-af64-59e5dde74bad\",\"event_body\":{\"transaction_id\":\"c34c8721-66a9-49f6-a229-284efcf88a02\",\"settled_at\":\"2022-03-11T14:00:32.933000Z\"}}" \
    http://localhost:7000/hook/d7a2c49d-110a-4ed2-a07d-8fdb3ea6424b
```

Modifying the `X-Tl-Webhook-Timestamp` header, the body or the path will cause the above signature to be invalid.
