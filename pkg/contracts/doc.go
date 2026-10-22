// Package contracts holds the Go types for the JSON schemas in contracts/schemas
// and the interfaces the agentgw packages implement against each other.
//
// Owned by the architect node. Workers import it and never edit it; a gap goes
// in the worker's done file under "Contract gaps".
//
// Every document type has a Version field whose value is the schema version
// ("1"). Field names and JSON tags mirror the schemas one to one;
// pkg/contracts/schema_test.go enforces that by round-tripping every example
// in contracts/examples through these types.
package contracts

// SchemaVersion is the current version of every schema in contracts/schemas.
const SchemaVersion = "1"
