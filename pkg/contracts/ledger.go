package contracts

import (
	"encoding/json"
	"time"
)

// Line type discriminators for the JSONL ledger.
const (
	LineTypeEntry      = "entry"
	LineTypeCheckpoint = "checkpoint"
)

// ZeroHash is the prev_hash of the first line of a ledger.
const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// EntryOutcome is what happened to a call, as recorded in the ledger.
type EntryOutcome string

const (
	EntryOK              EntryOutcome = "ok"               // forwarded; upstream answered (isError results included)
	EntryDenied          EntryOutcome = "denied"           // policy deny
	EntryBudgetExceeded  EntryOutcome = "budget_exceeded"  // Reserve refused
	EntryApprovalDenied  EntryOutcome = "approval_denied"  // a human said no
	EntryApprovalTimeout EntryOutcome = "approval_timeout" // nobody answered in time
	EntryError           EntryOutcome = "error"            // Forward failed; reservation released
)

// ApprovalDecision is a human's decision on one approval, bound to the call id
// and args hash. ApproverSig is the hex Ed25519 signature by the approver token
// over the JCS bytes of {"approval_id","args_hash","decision","ts"} (ts as the
// RFC 3339 UTC string); empty for surfaces without a key.
type ApprovalDecision struct {
	ApprovalID  string    `json:"approval_id"`
	CallID      string    `json:"call_id"`
	ArgsHash    string    `json:"args_hash"`
	Decision    string    `json:"decision"` // "approved" or "denied"
	ApproverID  string    `json:"approver_id"`
	Reason      string    `json:"reason"`
	Ts          time.Time `json:"ts"`
	Grant       *Grant    `json:"grant"` // nil unless the approver issued one
	ApproverSig string    `json:"approver_sig"`
}

// Decision values for ApprovalDecision.Decision.
const (
	DecisionApproved = "approved"
	DecisionDenied   = "denied"
)

// EntryAction is the call as stored: redacted args plus the hash of the raw args.
type EntryAction struct {
	Server   string          `json:"server"`
	Tool     string          `json:"tool"`
	Args     json.RawMessage `json:"args"` // raw on input to Append, redacted after
	ArgsHash string          `json:"args_hash"`
	// Multi-round-trip calls only (Call.InputResponses / RequestState); all
	// three absent otherwise. InputResponses is raw on input to Append,
	// redacted after; InputResponsesHash is SHA-256 of JCS(raw). ArgsHash is
	// unchanged by them.
	InputResponses     json.RawMessage `json:"input_responses,omitempty"`
	InputResponsesHash string          `json:"input_responses_hash,omitempty"`
	RequestState       string          `json:"request_state,omitempty"`
}

// EntryDecision is the policy decision plus the human decision, if any.
type EntryDecision struct {
	Outcome       Outcome           `json:"outcome"`
	RuleID        string            `json:"rule_id"`
	PolicyVersion string            `json:"policy_version"`
	GrantID       string            `json:"grant_id"`
	Approval      *ApprovalDecision `json:"approval"`
}

// EntryResult is the upstream result as stored. Content is nil (JSON null)
// and ResultHash is "" when nothing was forwarded.
type EntryResult struct {
	Content    json.RawMessage `json:"content"` // raw CallToolResult on input to Append, redacted after
	ResultHash string          `json:"result_hash"`
	Error      string          `json:"error"`
}

// EntryCost is what was reserved and what was settled.
type EntryCost struct {
	Estimated Money `json:"estimated"`
	Actual    Money `json:"actual"`
}

// Entry mirrors contracts/schemas/ledger-entry.schema.json. The schema's
// description fixes the hashing and signing rules.
type Entry struct {
	Version   string        `json:"version"`
	Type      string        `json:"type"` // LineTypeEntry
	ID        string        `json:"id"`   // ULID, set by Append
	Ts        time.Time     `json:"ts"`   // UTC, set by Append when zero
	PrevHash  string        `json:"prev_hash"`
	CallID    string        `json:"call_id"`
	Principal Principal     `json:"principal"`
	Action    EntryAction   `json:"action"`
	Decision  EntryDecision `json:"decision"`
	Outcome   EntryOutcome  `json:"outcome"`
	Result    EntryResult   `json:"result"`
	Cost      EntryCost     `json:"cost"`
	Signer    string        `json:"signer"` // hex Ed25519 public key
	Sig       string        `json:"sig"`    // hex Ed25519 signature
}

// CheckpointRange is the inclusive run of entries a checkpoint covers.
type CheckpointRange struct {
	FirstID string `json:"first_id"`
	LastID  string `json:"last_id"`
	Count   int    `json:"count"`
}

// Checkpoint mirrors contracts/schemas/checkpoint.schema.json. The schema's
// description fixes the Merkle construction.
type Checkpoint struct {
	Version  string          `json:"version"`
	Type     string          `json:"type"` // LineTypeCheckpoint
	ID       string          `json:"id"`
	Ts       time.Time       `json:"ts"`
	PrevHash string          `json:"prev_hash"`
	Range    CheckpointRange `json:"range"`
	Root     string          `json:"root"`
	Signer   string          `json:"signer"`
	Sig      string          `json:"sig"`
}

// VerifyReport is the result of verifying a ledger file offline.
type VerifyReport struct {
	OK          bool
	Entries     int    // entry lines verified
	Checkpoints int    // checkpoint lines verified
	Line        int    // 1-based line of the first failure; 0 when OK
	Reason      string // empty when OK; otherwise one of the reasons listed in tasks/phase1/ledger.md, including read_error for an I/O failure mid-stream (never OK on a partial read)
}
