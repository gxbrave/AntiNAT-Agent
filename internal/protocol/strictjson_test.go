package protocol

import (
	"errors"
	"strings"
	"testing"
)

type strictJSONNestedFixture struct {
	Value int64 `json:"value"`
}

type strictJSONMessageFixture struct {
	OperationID string                  `json:"operation_id"`
	Nested      strictJSONNestedFixture `json:"nested"`
	Values      []int64                 `json:"values"`
}

// Story 2 RED: duplicate keys, unknown fields, deep nesting, oversized
// values, and numeric overflow must all fail with stable error codes; the
// frozen valid baseline must pass.

func TestStrictJSONValidBaseline(t *testing.T) {
	if err := ValidateStrictJSON([]byte(`{"a":1,"b":"x"}`), nil); err != nil {
		t.Fatalf("baseline valid payload rejected: %v", err)
	}
	if err := ValidateStrictJSON([]byte(`{"a":1}`), map[string]FieldKind{"a": KindInt}); err != nil {
		t.Fatalf("schema-valid payload rejected: %v", err)
	}
}

// TestStrictJSONRejectsAmbiguous pins the frozen strict rules.
func TestStrictJSONRejectsAmbiguous(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		wantCode string
	}{
		{"duplicate-key", `{"a":1,"a":2}`, CodeDuplicateKey},
		{"trailing-garbage", `{"a":1} extra`, CodeTrailingGarbage},
		{"empty", ``, CodeEmpty},
		{"not-object", `[1,2,3]`, CodeNotObject},
		{"top-level-array", `{"a":[]}`, ""}, // arrays at nested level are allowed
		{"deep-nesting", `{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":{"k":{"l":{"m":{"n":{"o":{"p":{"q":1}}}}}}}}}}}}}}}}`, CodeTooDeep},
		{"out-of-range-number", `{"a":9223372036854775808}`, CodeNumberOverflow},
		{"negative-out-of-range", `{"a":-9223372036854775809}`, CodeNumberOverflow},
		{"int64-min-rejected", `{"a":-9223372036854775808}`, CodeNumberOverflow},
		{"fractional-number", `{"a":1.5}`, CodeNumberOverflow},
		{"exponential-number", `{"a":1e3}`, CodeNumberOverflow},
		{"number-in-string-field", `{"a":"x"}`, ""}, // valid shape; schema checks types
		{"unterminated", `{"a":1`, CodeMalformed},
		{"malformed", `{"a":}`, CodeMalformed},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStrictJSON([]byte(tc.raw), nil)
			if tc.wantCode == "" {
				if err != nil {
					t.Fatalf("expected valid shape, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected rejection for %q", tc.raw)
			}
			code := StrictJSONCode(err)
			if code != tc.wantCode {
				t.Fatalf("got code %q, want %q (err=%v)", code, tc.wantCode, err)
			}
		})
	}
}

// TestStrictJSONRejectsUnknownFields requires a schema.
func TestStrictJSONRejectsUnknownFields(t *testing.T) {
	schema := map[string]FieldKind{"a": KindInt}
	if err := ValidateStrictJSON([]byte(`{"a":1,"zz":2}`), schema); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
	if code := StrictJSONCode(ValidateStrictJSON([]byte(`{"a":1,"zz":2}`), schema)); code != CodeUnknownField {
		t.Fatalf("unknown-field code = %q, want %q", code, CodeUnknownField)
	}
	if err := ValidateStrictJSON([]byte(`{"a":1}`), schema); err != nil {
		t.Fatalf("schema-valid payload rejected: %v", err)
	}
	// Nested objects inside a schema field are shape-checked (any keys).
	if err := ValidateStrictJSON([]byte(`{"a":{"anything":true}}`), map[string]FieldKind{"a": KindObject}); err != nil {
		t.Fatalf("nested object rejected: %v", err)
	}
}

// TestStrictJSONKindChecks pins per-field kind enforcement.
func TestStrictJSONKindChecks(t *testing.T) {
	schema := map[string]FieldKind{"a": KindInt, "b": KindString, "c": KindStringArray, "d": KindHex}
	if err := ValidateStrictJSON([]byte(`{"a":"not-int","b":"x","c":[],"d":"abcd"}`), schema); err == nil {
		t.Fatal("string accepted for integer field")
	}
	if err := ValidateStrictJSON([]byte(`{"a":1,"b":2,"c":[],"d":"abcd"}`), schema); err == nil {
		t.Fatal("number accepted for string field")
	}
	if err := ValidateStrictJSON([]byte(`{"a":1,"b":"x","c":"not-array","d":"abcd"}`), schema); err == nil {
		t.Fatal("string accepted for string-array field")
	}
	if err := ValidateStrictJSON([]byte(`{"a":1,"b":"x","c":[],"d":"zz"}`), schema); err == nil {
		t.Fatal("non-hex accepted for hex field")
	}
	if err := ValidateStrictJSON([]byte(`{"a":1,"b":"x","c":["s"],"d":"abcd"}`), schema); err != nil {
		t.Fatalf("valid schema payload rejected: %v", err)
	}
	// Oversized string values are bounded by the payload cap.
	big := `{"b":"` + strings.Repeat("x", MaxPayloadBytes) + `"}`
	if err := ValidateStrictJSON([]byte(big), map[string]FieldKind{"b": KindString}); err == nil {
		t.Fatal("oversized value accepted")
	}
}

// TestStrictJSONDecode pins the decoding entry point and stable codes.
func TestStrictJSONDecode(t *testing.T) {
	got, err := DecodeStrictJSON([]byte(`{"a":1,"b":"x"}`), map[string]FieldKind{"a": KindInt, "b": KindString})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["a"] != int64(1) || got["b"] != "x" {
		t.Fatalf("decoded values mismatch: %v", got)
	}
	if _, err := DecodeStrictJSON([]byte(`{"a":1,"a":2}`), nil); err == nil {
		t.Fatal("duplicate keys accepted by DecodeStrictJSON")
	}
	// Stable codes are comparable sentinels.
	for _, want := range []string{
		CodeDuplicateKey, CodeUnknownField, CodeTooDeep, CodeNumberOverflow,
		CodeTrailingGarbage, CodeMalformed, CodeNotObject, CodeEmpty,
	} {
		if want == "" {
			t.Fatal("empty stable code")
		}
	}
	// Sentinel errors are exported and distinct.
	distinct := map[error]bool{
		ErrDuplicateKey: true, ErrUnknownField: true, ErrJSONTooDeep: true,
		ErrNumberOverflow: true, ErrTrailingGarbage: true, ErrMalformedJSON: true,
		ErrNotObject: true, ErrEmptyPayload: true,
	}
	if len(distinct) != 8 {
		t.Fatal("stable error sentinels must be distinct")
	}
	if !errors.Is(ValidateStrictJSON([]byte(`{"a":1,"a":2}`), nil), ErrDuplicateKey) {
		t.Fatal("duplicate-key error must be errors.Is-compatible")
	}
	if !errors.Is(ValidateStrictJSON([]byte(`{"a":1} extra`), nil), ErrTrailingGarbage) {
		t.Fatal("trailing-garbage error must be errors.Is-compatible")
	}
}

// R13 RED: semantic ingress must use one schema-aware decoder rather than a
// shape-only validation followed by json.Unmarshal. The shared entry point
// applies the frozen payload cap, duplicate/unknown/trailing/depth/integer
// rules recursively, including objects nested inside the message schema.
func TestDecodeStrictJSONIntoEnforcesFrozenIngressRules(t *testing.T) {
	var valid strictJSONMessageFixture
	if err := DecodeStrictJSONInto([]byte(`{"operation_id":"op-1","nested":{"value":7},"values":[1,2]}`), &valid); err != nil {
		t.Fatalf("valid semantic message rejected: %v", err)
	}
	if valid.OperationID != "op-1" || valid.Nested.Value != 7 || len(valid.Values) != 2 {
		t.Fatalf("decoded semantic message = %+v", valid)
	}

	deep := `{"operation_id":"op","nested":{"value":1},"values":` + strings.Repeat("[", MaxJSONDepth+1) + `1` + strings.Repeat("]", MaxJSONDepth+1) + `}`
	oversize := `{"operation_id":"` + strings.Repeat("x", MaxPayloadBytes) + `","nested":{"value":1},"values":[]}`
	cases := []struct {
		name string
		raw  string
	}{
		{"duplicate-top-level", `{"operation_id":"a","operation_id":"b","nested":{"value":1},"values":[]}`},
		{"duplicate-nested", `{"operation_id":"a","nested":{"value":1,"value":2},"values":[]}`},
		{"unknown-top-level", `{"operation_id":"a","nested":{"value":1},"values":[],"extra":true}`},
		{"unknown-nested", `{"operation_id":"a","nested":{"value":1,"extra":true},"values":[]}`},
		{"trailing-object", `{"operation_id":"a","nested":{"value":1},"values":[]} {}`},
		{"fractional-integer", `{"operation_id":"a","nested":{"value":1.5},"values":[]}`},
		{"exponential-integer", `{"operation_id":"a","nested":{"value":1e3},"values":[]}`},
		{"int64-min", `{"operation_id":"a","nested":{"value":-9223372036854775808},"values":[]}`},
		{"depth", deep},
		{"oversize", oversize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var dst strictJSONMessageFixture
			if err := DecodeStrictJSONInto([]byte(tc.raw), &dst); err == nil {
				t.Fatalf("ambiguous semantic payload accepted: %s", tc.raw)
			}
		})
	}
}
