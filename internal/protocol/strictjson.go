// Strict JSON payload decoding (docs/protocol.md §3.4).
//
// Semantic JSON has two deliberately separate checks. The token pass below
// rejects ambiguity recursively (including arrays), while DecodeStrictJSONInto
// performs the typed, schema-aware decode. Keeping the passes separate means a
// caller cannot accidentally use encoding/json's last-key-wins behaviour or
// silently accept a trailing value before it reaches a state machine.
package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

const (
	CodeDuplicateKey    = "duplicate_key"
	CodeUnknownField    = "unknown_field"
	CodeTooDeep         = "depth_exceeded"
	CodeNumberOverflow  = "number_overflow"
	CodeTrailingGarbage = "trailing_garbage"
	CodeMalformed       = "malformed"
	CodeNotObject       = "not_object"
	CodeEmpty           = "empty"
	CodeKindMismatch    = "kind_mismatch"
	CodeUnexpectedToken = "unexpected_token"
	CodePayloadTooLarge = "payload_too_large"
)

var (
	ErrEmptyPayload    = errors.New("protocol: json payload is empty")
	ErrDuplicateKey    = errors.New("protocol: duplicate JSON key")
	ErrUnknownField    = errors.New("protocol: unknown JSON field")
	ErrJSONTooDeep     = errors.New("protocol: json nesting depth exceeded")
	ErrNumberOverflow  = errors.New("protocol: json number out of range")
	ErrTrailingGarbage = errors.New("protocol: trailing content after JSON object")
	ErrMalformedJSON   = errors.New("protocol: malformed JSON")
	ErrNotObject       = errors.New("protocol: json payload must be a single object")
	ErrKindMismatch    = errors.New("protocol: json field kind mismatch")
	ErrUnexpectedToken = errors.New("protocol: unexpected JSON token")
	ErrPayloadTooLarge = errors.New("protocol: json payload exceeds maximum size")
)

type StrictJSONError struct {
	Code_ string
	Field string
	Err   error
}

func (e *StrictJSONError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("protocol: strict json %s: field %q: %v", e.Code_, e.Field, e.Err)
	}
	return fmt.Sprintf("protocol: strict json %s: %v", e.Code_, e.Err)
}
func (e *StrictJSONError) Unwrap() error { return e.Err }
func (e *StrictJSONError) Code() string  { return e.Code_ }

func StrictJSONCode(err error) string {
	if err == nil {
		return ""
	}
	var se *StrictJSONError
	if errors.As(err, &se) {
		return se.Code()
	}
	return ""
}

type FieldKind int

const (
	KindString FieldKind = iota
	KindInt
	KindBool
	KindHex
	KindStringArray
	KindObject
	KindAny
)

func ValidateStrictJSON(payload []byte, schema map[string]FieldKind) error {
	_, err := decodeStrict(payload, schema)
	return err
}

func DecodeStrictJSON(payload []byte, schema map[string]FieldKind) (map[string]any, error) {
	return decodeStrict(payload, schema)
}

// DecodeStrictJSONInto is the sole typed semantic JSON ingress helper. It
// applies the protocol byte/depth/number rules first, then DisallowUnknownFields
// on the destination's complete recursive Go schema and finally requires EOF.
func DecodeStrictJSONInto(payload []byte, dst any) error {
	if dst == nil {
		return strictError(CodeKindMismatch, ErrKindMismatch)
	}
	rv := reflect.ValueOf(dst)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return strictError(CodeKindMismatch, ErrKindMismatch)
	}
	if _, err := decodeStrict(payload, nil); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return typedDecodeError(err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return strictError(CodeTrailingGarbage, ErrTrailingGarbage)
	}
	return nil
}

func strictError(code string, cause error) error {
	return &StrictJSONError{Code_: code, Err: cause}
}

func decodeStrict(payload []byte, schema map[string]FieldKind) (map[string]any, error) {
	if len(payload) == 0 {
		return nil, strictError(CodeEmpty, ErrEmptyPayload)
	}
	if len(payload) > MaxPayloadBytes {
		return nil, &StrictJSONError{Code_: CodePayloadTooLarge, Err: fmt.Errorf("%w: %d bytes > %d", ErrPayloadTooLarge, len(payload), MaxPayloadBytes)}
	}
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	tok, err := d.Token()
	if err != nil {
		return nil, jsonDecodeError(err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, strictError(CodeNotObject, ErrNotObject)
	}
	out := map[string]any{}
	if err := walkObject(d, schema, 0, out); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, strictError(CodeTrailingGarbage, ErrTrailingGarbage)
	}
	return out, nil
}

func jsonDecodeError(err error) error {
	if errors.Is(err, io.EOF) {
		return strictError(CodeMalformed, ErrMalformedJSON)
	}
	var syn *json.SyntaxError
	if errors.As(err, &syn) {
		return strictError(CodeMalformed, ErrMalformedJSON)
	}
	return strictError(CodeMalformed, ErrMalformedJSON)
}

func typedDecodeError(err error) error {
	var unknown *json.UnmarshalTypeError
	if errors.As(err, &unknown) {
		if strings.Contains(strings.ToLower(err.Error()), "cannot unmarshal number") {
			return strictError(CodeNumberOverflow, ErrNumberOverflow)
		}
		return strictError(CodeKindMismatch, ErrKindMismatch)
	}
	if strings.Contains(err.Error(), "unknown field") {
		return strictError(CodeUnknownField, ErrUnknownField)
	}
	return jsonDecodeError(err)
}

func walkObject(d *json.Decoder, schema map[string]FieldKind, depth int, out map[string]any) error {
	if depth > MaxJSONDepth {
		return strictError(CodeTooDeep, ErrJSONTooDeep)
	}
	seen := make(map[string]struct{})
	for {
		tok, err := d.Token()
		if err != nil {
			return jsonDecodeError(err)
		}
		if delim, ok := tok.(json.Delim); ok && delim == '}' {
			return nil
		}
		key, ok := tok.(string)
		if !ok {
			return strictError(CodeUnexpectedToken, ErrUnexpectedToken)
		}
		if _, exists := seen[key]; exists {
			return &StrictJSONError{Code_: CodeDuplicateKey, Field: key, Err: ErrDuplicateKey}
		}
		seen[key] = struct{}{}
		kind, allowed := schema[key]
		if !allowed {
			if schema != nil {
				return &StrictJSONError{Code_: CodeUnknownField, Field: key, Err: ErrUnknownField}
			}
			kind = KindAny
		}
		value, err := walkValue(d, kind, depth+1)
		if err != nil {
			return err
		}
		out[key] = value
	}
}

func walkValue(d *json.Decoder, kind FieldKind, depth int) (any, error) {
	if depth > MaxJSONDepth {
		return nil, strictError(CodeTooDeep, ErrJSONTooDeep)
	}
	tok, err := d.Token()
	if err != nil {
		return nil, jsonDecodeError(err)
	}
	switch value := tok.(type) {
	case json.Delim:
		switch value {
		case '{':
			if kind != KindAny && kind != KindObject {
				return nil, strictError(CodeKindMismatch, ErrKindMismatch)
			}
			obj := map[string]any{}
			if err := walkObject(d, nil, depth, obj); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			if kind != KindAny && kind != KindStringArray {
				return nil, strictError(CodeKindMismatch, ErrKindMismatch)
			}
			arr := make([]any, 0)
			for {
				peek, err := d.Token()
				if err != nil {
					return nil, jsonDecodeError(err)
				}
				if close, ok := peek.(json.Delim); ok && close == ']' {
					return arr, nil
				}
				// Token has already been consumed. Validate and recursively walk
				// containers through a small token-preserving helper.
				item, err := walkTokenValue(d, peek, func() FieldKind {
					if kind == KindStringArray {
						return KindString
					}
					return KindAny
				}(), depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, item)
			}
		default:
			return nil, strictError(CodeUnexpectedToken, ErrUnexpectedToken)
		}
	case string:
		if err := checkScalarKind(kind, value); err != nil {
			return nil, err
		}
		return value, nil
	case json.Number:
		if kind != KindAny && kind != KindInt {
			return nil, strictError(CodeKindMismatch, ErrKindMismatch)
		}
		if !IsBoundedJSONNumber(value) {
			return nil, strictError(CodeNumberOverflow, ErrNumberOverflow)
		}
		parsed, err := value.Int64()
		if err != nil {
			return nil, strictError(CodeNumberOverflow, ErrNumberOverflow)
		}
		return parsed, nil
	case bool:
		if kind != KindAny && kind != KindBool {
			return nil, strictError(CodeKindMismatch, ErrKindMismatch)
		}
		return value, nil
	case nil:
		// Nullability is decided by the typed pass (pointer/interface fields can
		// be null); the structural pass still consumes it safely.
		return nil, nil
	default:
		return nil, strictError(CodeUnexpectedToken, ErrUnexpectedToken)
	}
}

func walkTokenValue(d *json.Decoder, tok json.Token, kind FieldKind, depth int) (any, error) {
	if depth > MaxJSONDepth {
		return nil, strictError(CodeTooDeep, ErrJSONTooDeep)
	}
	switch value := tok.(type) {
	case json.Delim:
		switch value {
		case '{':
			if kind != KindAny && kind != KindObject {
				return nil, strictError(CodeKindMismatch, ErrKindMismatch)
			}
			obj := map[string]any{}
			if err := walkObject(d, nil, depth, obj); err != nil {
				return nil, err
			}
			return obj, nil
		case '[':
			if kind != KindAny {
				return nil, strictError(CodeKindMismatch, ErrKindMismatch)
			}
			arr := make([]any, 0)
			for {
				next, err := d.Token()
				if err != nil {
					return nil, jsonDecodeError(err)
				}
				if close, ok := next.(json.Delim); ok && close == ']' {
					return arr, nil
				}
				item, err := walkTokenValue(d, next, KindAny, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, item)
			}
		default:
			return nil, strictError(CodeUnexpectedToken, ErrUnexpectedToken)
		}
	case string:
		if err := checkScalarKind(kind, value); err != nil {
			return nil, err
		}
		return value, nil
	case json.Number:
		if kind != KindAny && kind != KindInt {
			return nil, strictError(CodeKindMismatch, ErrKindMismatch)
		}
		if !IsBoundedJSONNumber(value) {
			return nil, strictError(CodeNumberOverflow, ErrNumberOverflow)
		}
		i, err := value.Int64()
		if err != nil {
			return nil, strictError(CodeNumberOverflow, ErrNumberOverflow)
		}
		return i, nil
	case bool:
		if kind != KindAny && kind != KindBool {
			return nil, strictError(CodeKindMismatch, ErrKindMismatch)
		}
		return value, nil
	case nil:
		return nil, nil
	default:
		return nil, strictError(CodeUnexpectedToken, ErrUnexpectedToken)
	}
}

func checkScalarKind(kind FieldKind, value string) error {
	switch kind {
	case KindAny, KindString:
		return nil
	case KindHex:
		if _, err := hex.DecodeString(value); err != nil {
			return strictError(CodeKindMismatch, ErrKindMismatch)
		}
		return nil
	default:
		return strictError(CodeKindMismatch, ErrKindMismatch)
	}
}

func IsBoundedJSONNumber(n json.Number) bool {
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return false
	}
	negative := strings.HasPrefix(s, "-")
	if negative {
		s = s[1:]
	}
	if len(s) == 0 {
		return false
	}
	const maxI64 = "9223372036854775807"
	if len(s) < len(maxI64) || (len(s) == len(maxI64) && s <= maxI64) {
		// The one excluded value is int64 minimum. Its magnitude has one more
		// than maxI64 and is therefore handled explicitly below.
		return !(negative && len(s) == len(maxI64)+1 && s == "9223372036854775808")
	}
	return false
}
