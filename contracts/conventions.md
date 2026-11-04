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
  redirect would carry injected credentials to another host. An upstream
  with an `auth` block (docs/adr/0012) never receives the client's
  `Authorization` header: the proxy deletes it and applies the gateway-held
  credential when it builds each outbound request; if the credential cannot
  be produced nothing is forwarded.
- **HTTPS for credentials** (config load): an upstream with an `auth` block
  must have an https `url`, or an http `url` whose host is exactly
  `127.0.0.1`, `localhost` or `::1`. The same holds for `token_url` (kind
  `client_credentials`) and `issuer` (kind `authorization_code`; `issuer`
  additionally has no query, fragment or userinfo). A relative URL or one
  without a host fails too. A violation is a config load error; upstreams
  without `auth` are not restricted. Rationale: the credential travels with
  every request.
- **HTTP listener guard** (proxy): before any route matches and before the
  body is read, every request on the `listen` address, any method (GET opens
  a stream), passes two checks. Host: when the listener address is loopback,
  the request `Host` must be `localhost` (case-insensitive) or a loopback IP,
  with or without a port; listeners on other addresses do not check `Host`,
  since the gateway cannot know its public name. Origin: a request with an
  `Origin` header is refused unless the Origin's host:port equals `Host`
  under `strings.EqualFold` (textual, no default-port normalisation); `null`
  is refused; a request without `Origin` is allowed, since non-browser MCP
  clients send none. A refused request is answered HTTP 403 with a JSON-RPC
  error, id `null`, code -32600, and nothing is forwarded. Rationale: the
  gateway holds upstream credentials, so a web page must not be able to spend
  them through a cross-site request or DNS rebinding.
