One example document per schema in `../schemas/`. Named `<schema>.example.json`.
`common.schema.json` holds shared `$defs` and has no example.

`pkg/contracts/schema_test.go` validates every example against its schema and
round-trips it through the Go types. Hashes, keys and signatures in the examples
are well-formed placeholders, not verifiable values.
