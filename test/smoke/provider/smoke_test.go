// Package provider_test contains smoke tests for the provider proto contract.
//
// Two categories of tests:
//
//  1. Constraint validation — protovalidate rules on provider messages catch
//     missing/empty fields.  If a constraint is accidentally removed from a
//     .proto file, the corresponding test breaks.
//  2. Oneof exhaustion — protobuf reflection verifies the exact number of
//     ProviderOutput.algorithm_output arms.  Adding a new arm fails this test,
//     forcing the developer to update both the expected count and the core's
//     dispatch switch.
package provider_test

import (
	"errors"
	"testing"

	protovalidate "buf.build/go/protovalidate"
	metapb "github.com/agile-crypto/citius-server/gen/go/api/messages"
	typespb "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"google.golang.org/protobuf/proto"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func validator(t *testing.T) protovalidate.Validator {
	t.Helper()
	v, err := protovalidate.New()
	if err != nil {
		t.Fatalf("protovalidate.New: %v", err)
	}
	return v
}

func mustPass(t *testing.T, v protovalidate.Validator, msg proto.Message) {
	t.Helper()
	if err := v.Validate(msg); err != nil {
		t.Errorf("%T should be valid: %v", msg, err)
	}
}

// mustFailField asserts that validation fails BECAUSE of a violation on
// wantField specifically — not merely that validation fails for some reason.
//
// A message can be invalid in several ways at once; asserting only "err != nil"
// lets a test keep passing after the field it names stops being enforced (e.g.
// a constraint is accidentally dropped from the .proto) as long as some other
// constraint still fires.  Checking the violated field closes that gap.
func mustFailField(t *testing.T, v protovalidate.Validator, msg proto.Message, wantField string) {
	t.Helper()
	err := v.Validate(msg)
	if err == nil {
		t.Fatalf("%T should be invalid, but passed validation", msg)
	}
	var valErr *protovalidate.ValidationError
	if !errors.As(err, &valErr) {
		t.Fatalf("%T: expected *protovalidate.ValidationError, got %T: %v", msg, err, err)
	}
	for _, viol := range valErr.Violations {
		if viol.FieldDescriptor != nil && string(viol.FieldDescriptor.Name()) == wantField {
			return
		}
	}
	t.Fatalf("%T: expected a violation on field %q, got: %v", msg, wantField, err)
}

// ============================================================================
// Protovalidate constraint validation
// ============================================================================

// --- GenerateKeyRequest ---

func TestGenerateKeyRequest_validate_valid(t *testing.T) {
	v := validator(t)
	mustPass(t, v, &providerpb.GenerateKeyRequest{
		Algorithm: &typespb.AlgorithmDetails{
			Algorithm: &typespb.AlgorithmDetails_Ecdsa{
				Ecdsa: &typespb.EcdsaParams{
					Curve: typespb.EllipticCurve_ELLIPTIC_CURVE_P256,
					Hash:  typespb.HashAlgorithm_HASH_ALGORITHM_SHA256,
				},
			},
		},
	})
}

func TestGenerateKeyRequest_validate_nilAlgorithm(t *testing.T) {
	v := validator(t)
	mustFailField(t, v, &providerpb.GenerateKeyRequest{}, "algorithm")
}

// --- GenerateKeyResponse ---

func TestGenerateKeyResponse_validate_emptyKeyMaterial(t *testing.T) {
	v := validator(t)
	mustFailField(t, v, &providerpb.GenerateKeyResponse{}, "key_material")
}

// --- SignRequest ---

func TestSignRequest_validate_valid(t *testing.T) {
	v := validator(t)
	mustPass(t, v, &providerpb.SignRequest{
		KeyMaterial: []byte("opaque-key"),
		Input:       []byte("message"),
		Algorithm: &typespb.AlgorithmDetails{
			Algorithm: &typespb.AlgorithmDetails_Ecdsa{
				Ecdsa: &typespb.EcdsaParams{
					Curve: typespb.EllipticCurve_ELLIPTIC_CURVE_P256,
					Hash:  typespb.HashAlgorithm_HASH_ALGORITHM_SHA256,
				},
			},
		},
	})
}

func TestSignRequest_validate_emptyKeyMaterial(t *testing.T) {
	v := validator(t)
	mustFailField(t, v, &providerpb.SignRequest{
		Input: []byte("message"),
	}, "key_material")
}

// TestSignRequest_validate_emptyInput proves empty input passes validation —
// signing an empty message is a legitimate, well-defined operation, so
// SignRequest.input intentionally carries no min_len constraint.
func TestSignRequest_validate_emptyInput(t *testing.T) {
	v := validator(t)
	mustPass(t, v, &providerpb.SignRequest{
		KeyMaterial: []byte("opaque-key"),
		Input:       []byte{},
		Algorithm: &typespb.AlgorithmDetails{
			Algorithm: &typespb.AlgorithmDetails_Ecdsa{
				Ecdsa: &typespb.EcdsaParams{
					Curve: typespb.EllipticCurve_ELLIPTIC_CURVE_P256,
					Hash:  typespb.HashAlgorithm_HASH_ALGORITHM_SHA256,
				},
			},
		},
	})
}

// --- SignResponse ---

func TestSignResponse_validate_emptySignature(t *testing.T) {
	v := validator(t)
	mustFailField(t, v, &providerpb.SignResponse{}, "signature")
}

// --- EncryptRequest ---

func TestEncryptRequest_validate_emptyPlaintext(t *testing.T) {
	v := validator(t)
	mustFailField(t, v, &providerpb.EncryptRequest{
		KeyMaterial: []byte("opaque-key"),
	}, "plaintext")
}

// --- EncryptResponse ---

func TestEncryptResponse_validate_emptyCiphertext(t *testing.T) {
	v := validator(t)
	mustFailField(t, v, &providerpb.EncryptResponse{}, "ciphertext")
}

// --- ProviderInfo ---

func TestProviderInfo_validate_valid(t *testing.T) {
	v := validator(t)
	mustPass(t, v, &providerpb.ProviderInfo{
		Name:    "go-crypto",
		Version: "1.0.0",
		Type:    "software",
	})
}

func TestProviderInfo_validate_emptyName(t *testing.T) {
	v := validator(t)
	mustFailField(t, v, &providerpb.ProviderInfo{
		Version: "1.0.0",
		Type:    "software",
	}, "name")
}

// --- StreamingSignInitRequest ---

func TestStreamingSignInitRequest_validate_emptySessionId(t *testing.T) {
	v := validator(t)
	mustFailField(t, v, &providerpb.StreamingSignInitRequest{
		KeyMaterial: []byte("opaque-key"),
	}, "session_id")
}

// ============================================================================
// Oneof exhaustion — ProviderOutput.algorithm_output
// ============================================================================

// TestProviderOutput_algorithmOutputArms uses protobuf reflection to verify
// the exact number of arms in the algorithm_output oneof.  When a new arm
// is added, this test fails — forcing the developer to update the expected
// count AND the core's dispatch switch.
func TestProviderOutput_algorithmOutputArms(t *testing.T) {
	md := (&metapb.ProviderOutput{}).ProtoReflect().Descriptor()
	ao := md.Oneofs().ByName("algorithm_output")
	if ao == nil {
		t.Fatal("algorithm_output oneof not found on ProviderOutput")
	}

	const expectedArms = 7 // no_output, aead, block_cipher, counter_mode, stream_cipher, kdf, vendor
	if got := ao.Fields().Len(); got != expectedArms {
		t.Fatalf("algorithm_output has %d arms, expected %d — update this test and the core switch", got, expectedArms)
	}

	// Verify each arm round-trips through marshal/unmarshal.
	cases := []struct {
		name string
		po   *metapb.ProviderOutput
	}{
		{"no_output", &metapb.ProviderOutput{
			AlgorithmOutput: &metapb.ProviderOutput_NoOutput{NoOutput: &metapb.NoAlgorithmOutput{}},
		}},
		{"aead_output", &metapb.ProviderOutput{
			AlgorithmOutput: &metapb.ProviderOutput_AeadOutput{AeadOutput: &metapb.AeadOutput{
				Nonce: []byte("n"), TagLengthBytes: 16,
			}},
		}},
		{"block_cipher_output", &metapb.ProviderOutput{
			AlgorithmOutput: &metapb.ProviderOutput_BlockCipherOutput{BlockCipherOutput: &metapb.BlockCipherOutput{
				Iv: []byte("0123456789abcdef"),
			}},
		}},
		{"counter_mode_output", &metapb.ProviderOutput{
			AlgorithmOutput: &metapb.ProviderOutput_CounterModeOutput{CounterModeOutput: &metapb.CounterModeOutput{
				CounterBlock: make([]byte, 16), CounterBits: 32,
			}},
		}},
		{"stream_cipher_output", &metapb.ProviderOutput{
			AlgorithmOutput: &metapb.ProviderOutput_StreamCipherOutput{StreamCipherOutput: &metapb.StreamCipherOutput{
				Nonce: []byte("nonce12b"),
			}},
		}},
		{"kdf_output", &metapb.ProviderOutput{
			AlgorithmOutput: &metapb.ProviderOutput_KdfOutput{KdfOutput: &metapb.KdfOutput{
				Salt: []byte("random-salt"),
			}},
		}},
		{"vendor_output", &metapb.ProviderOutput{
			AlgorithmOutput: &metapb.ProviderOutput_VendorOutput{VendorOutput: &metapb.VendorOutput{
				Parameters: map[string][]byte{"k": []byte("v")},
			}},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := proto.Marshal(tc.po)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got := new(metapb.ProviderOutput)
			if err := proto.Unmarshal(b, got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got.AlgorithmOutput == nil {
				t.Error("algorithm_output nil after round-trip")
			}
		})
	}
}
