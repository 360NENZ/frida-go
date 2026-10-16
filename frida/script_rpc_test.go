package frida

import "testing"

func TestGetRPCResponse(t *testing.T) {
	id, value, ok := getRPCResponse(`{"type":"send","payload":["abc","ok",42]}`)
	if !ok || id != "abc" || value != float64(42) {
		t.Fatalf("unexpected response: %q, %v, %v", id, value, ok)
	}

	for _, message := range []string{
		`{"type":"log","payload":["abc","ok",42]}`,
		`{"type":"send","payload":["abc","call",42]}`,
		`{"type":"send","payload":[42,"ok",42]}`,
		`{"type":"send","payload":{"message":"unrelated"}}`,
		`not json`,
	} {
		if _, _, valid := getRPCResponse(message); valid {
			t.Fatalf("accepted non-RPC message: %s", message)
		}
	}
}
