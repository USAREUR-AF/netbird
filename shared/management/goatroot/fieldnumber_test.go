package goatroot

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// syncResponseFieldNumbers returns the field numbers SyncResponse declares in
// upstream's management.proto.
func syncResponseFieldNumbers(t *testing.T) map[int]string {
	t.Helper()
	src, err := os.ReadFile("../proto/management.proto")
	require.NoError(t, err)
	return syncResponseFieldNumbersIn(t, string(src))
}

func syncResponseFieldNumbersIn(t *testing.T, text string) map[int]string {
	t.Helper()
	start := regexp.MustCompile(`(?m)^message\s+SyncResponse\s*\{`).FindStringIndex(text)
	require.NotNil(t, start, "management.proto declares SyncResponse")

	// Walk to the brace that closes the message, counting nested blocks.
	depth, end := 0, -1
	for i := start[1] - 1; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
		}
		if depth == 0 {
			end = i
			break
		}
	}
	require.Greater(t, end, start[1], "SyncResponse is closed")

	out := map[int]string{}
	field := regexp.MustCompile(`(?m)^\s*(?:repeated\s+|optional\s+)?[\w.<>, ]+\s+(\w+)\s*=\s*(\d+)\s*[;\[]`)
	for _, m := range field.FindAllStringSubmatch(text[start[1]:end], -1) {
		var n int
		for _, c := range m[2] {
			n = n*10 + int(c-'0')
		}
		out[n] = m[1]
	}
	reserved := regexp.MustCompile(`(?m)^\s*reserved\s+([^;]+);`)
	for _, m := range reserved.FindAllStringSubmatch(text[start[1]:end], -1) {
		out[-1] = "reserved " + strings.TrimSpace(m[1])
	}
	return out
}

// TestSyncResponseFieldUndeclaredUpstream fails when upstream's SyncResponse
// declares the field number the root document travels in, so an upstream sync
// cannot silently give that number another meaning.
func TestSyncResponseRootFieldUndeclaredUpstream(t *testing.T) {
	fields := syncResponseFieldNumbers(t)
	require.NotEmpty(t, fields, "the parser found SyncResponse's fields")
	require.Contains(t, fields, 5, "the parser sees the NetworkMap field (5)")
	name, declared := fields[int(SyncResponseField)]
	require.False(t, declared, "upstream SyncResponse now declares field %d (%s); move the root document to an unused number", SyncResponseField, name)
	if r, ok := fields[-1]; ok {
		require.NotContains(t, r, "1002", "upstream reserves field 1002 in SyncResponse: %s", r)
	}
}

// TestSyncResponseFieldParserSeesAPlantedField proves the guard can fail.
func TestSyncResponseRootFieldParserSeesAPlantedField(t *testing.T) {
	planted := `message SyncResponse {
  NetbirdConfig netbirdConfig = 1;
  NetworkMap networkMap = 5;
  message Inner { int32 x = 1; }
  bytes somethingNew = 1002;
}
message Other { int32 y = 1001; }`
	fields := syncResponseFieldNumbersIn(t, planted)
	require.Equal(t, "somethingNew", fields[1002])
	require.NotContains(t, fields, 1001, "fields of other messages are not counted")
}
