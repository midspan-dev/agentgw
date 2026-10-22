# Gateway conventions

Rules the gateway applies that no schema expresses.

- **Built-in redaction** (ledger node) always applies before `config.redaction`:
  field names `password`, `passwd`, `secret`, `token`, `api_key`, `apikey`,
  `authorization`, `access_token`, `refresh_token`, `private_key`
  (case-insensitive, any depth, also inside arrays); patterns
  `(?i)bearer\s+[A-Za-z0-9._~+/=-]+`, `sk-[A-Za-z0-9_-]{8,}`, `AKIA[0-9A-Z]{16}`,
  `\b[0-9a-fA-F]{32,}\b`. Replacement is the string `[REDACTED]`
  (`contracts.Redacted`). Redaction never touches hashes.
- **Forwarding rule** (proxy, http-creds, any future relay): the gateway
  forwards only messages it has parsed strictly (case-sensitive field names,
  duplicate names rejected, exactly one JSON object per stdio line, unknown
  top-level JSON-RPC members rejected) and re-serialised from that parse. For
  tools/call the allowed `params` members are exactly `name`, `arguments`,
  `_meta`, `inputResponses`, `requestState` (go-sdk v1.8.0 CallToolParams);
  any other member, `task` included, is -32602. Numbers anywhere in
  `arguments` or `inputResponses` that are not finite IEEE-754 doubles
  (I-JSON, RFC 7493; what `gowebpki/jcs` can transform) are -32602 too, so
  every call that reaches the Interceptor can be recorded; hosts without the
  proxy in front (sdk-api, demo) canonicalise before pricing for the same
  reason. Key collisions (gap-006): two distinct keys of the same JSON
  object, at any depth of `arguments` or `inputResponses` (arrays included),
  collide when `strings.EqualFold(norm.NFC.String(k1), norm.NFC.String(k2))`
  holds — Unicode simple case folding after NFC. A colliding object is
  -32602 at the proxy; hosts without the proxy deny it with
  `evaluation-error`, reason `argument keys collide: <k1>, <k2>`. The proxy
  exports this validator (`proxy.ValidateParams`) and every host uses it.
  Client bytes are never copied upstream. JSON-RPC ids are canonicalised (numbers to their shortest form,
  strings verbatim) both for matching upstream responses to requests and for
  refusing a request whose id is already in flight on the same stdio
  connection (stateless HTTP has no cross-request id space). The gateway never
  follows upstream redirects: a 3xx from an upstream is an upstream error, on
  tools/call and passthrough alike. Anything that fails the parse is answered
  with a JSON-RPC error or dropped, never forwarded. Rationale: a parser
  differential between the gateway and the upstream is a policy bypass, and a
  redirect would carry injected credentials to another host.
