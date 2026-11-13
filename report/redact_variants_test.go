package report

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func redactionVariants(t *testing.T, secret string) map[string]string {
	t.Helper()
	encodedJSON, err := json.Marshal(secret)
	require.NoError(t, err)
	return map[string]string{
		"raw":            secret,
		"json":           string(encodedJSON[1 : len(encodedJSON)-1]),
		"query":          url.QueryEscape(secret),
		"path":           url.PathEscape(secret),
		"base64":         base64.StdEncoding.EncodeToString([]byte(secret)),
		"raw base64":     base64.RawStdEncoding.EncodeToString([]byte(secret)),
		"url base64":     base64.URLEncoding.EncodeToString([]byte(secret)),
		"raw url base64": base64.RawURLEncoding.EncodeToString([]byte(secret)),
	}
}

func variantFinding(t *testing.T, secret string) Finding {
	t.Helper()
	variants := redactionVariants(t, secret)
	analysis := Analysis{
		Status:       ValidationStatusValid,
		StatusReason: "raw " + variants["raw"] + " query " + variants["query"],
		StatusMetadata: map[string]any{
			"url":      "https://example.invalid/?token=" + variants["query"],
			"json":     map[string]string{"token": variants["json"]},
			"base64":   []string{variants["base64"], variants["raw base64"]},
			"urlbase":  []any{variants["url base64"], variants["raw url base64"]},
			"path":     variants["path"],
			"embedded": "prefix" + variants["base64"] + "suffix",
		},
		Reason: "echo " + variants["base64"],
		Metadata: map[string]any{
			"echo": "payload " + variants["raw base64"],
			"nested": map[string]any{
				"token": variants["url base64"],
			},
		},
		Debug: map[string]any{
			"resp_body": "message: " + variants["query"],
		},
		Identity: &AnalysisIdentity{
			ID:       "id-" + variants["base64"],
			Username: "user-" + variants["json"],
			Account:  &AnalysisAccount{ID: "acct", Domains: []string{variants["path"]}},
		},
	}
	return Finding{
		RuleID:      "rule-id",
		Description: "description with " + variants["base64"],
		Confidence:  "high",
		Match: Match{
			Full:     "token=" + secret + " b64=" + variants["base64"],
			Value:    secret,
			Line:     "line token=" + variants["query"] + " and " + variants["json"],
			Context:  "ctx " + variants["raw url base64"],
			Captures: map[string]string{"token": secret, "encoded": variants["base64"]},
		},
		Attributes: map[string]string{"encoded": variants["raw base64"], "safe": "metadata"},
		Location:   Location{Path: "dir/" + url.PathEscape(secret) + ".env"},
		Tags:       []string{variants["base64"]},
		Analysis:   analysis,
		ComponentSets: []ComponentSet{{
			Analysis: analysis,
			Components: []ComponentFinding{{
				RuleID:   "component-rule",
				Match:    Match{Full: "b64 " + variants["base64"], Value: secret, Line: variants["query"], Captures: map[string]string{"token": variants["json"]}},
				Location: Location{Path: variants["path"]},
			}},
		}},
	}
}

func assertNoVariantLeak(t *testing.T, secret, data string) {
	t.Helper()
	for name, variant := range redactionVariants(t, secret) {
		assert.NotContains(t, data, variant, "encoded variant %s leaked", name)
	}
}

func TestRedactCoversEncodedEquivalents(t *testing.T) {
	const secret = `ak/secret+value="x"&a<b>`
	original := variantFinding(t, secret)
	original.Match.Fingerprint = "fp-primary"
	original.ComponentSets[0].Components[0].Match.Fingerprint = "fp-component"

	for _, percent := range []uint{50, 100} {
		t.Run(fmt.Sprintf("percent_%d", percent), func(t *testing.T) {
			redacted := original.RedactedCopy(percent)

			data, err := json.Marshal(redacted)
			require.NoError(t, err)
			assertNoVariantLeak(t, secret, string(data))

			assert.Equal(t, "fp-primary", redacted.Match.Fingerprint, "fingerprints must be preserved")
			assert.Equal(t, "fp-component", redacted.ComponentSets[0].Components[0].Match.Fingerprint)
			assert.Equal(t, "rule-id", redacted.RuleID)
			assert.Equal(t, "high", redacted.Confidence)
			assert.Equal(t, ValidationStatusValid, redacted.Analysis.Status)
			assert.Equal(t, "metadata", redacted.Attributes["safe"], "non-secret metadata stays intact")

			component := redacted.ComponentSets[0].Components[0]
			wantValue := MaskSecret(secret, percent)
			if percent == 100 {
				wantValue = "REDACTED"
			}
			assert.Equal(t, wantValue, component.Match.Value)
			assert.NotContains(t, component.Match.Line, secret)

			for _, analysis := range []Analysis{redacted.Analysis, redacted.ComponentSets[0].Analysis} {
				assert.Equal(t, "acct", analysis.Identity.Account.ID)
				assert.Equal(t, "message: [redacted]", analysis.Debug["resp_body"])
			}
		})
	}
}

func TestRedactEncodedEquivalentsAlwaysFullyMasked(t *testing.T) {
	const secret = "abcdefghijklmnop"
	original := variantFinding(t, secret)

	redacted := original.RedactedCopy(50)

	assert.Equal(t, MaskSecret(secret, 50), redacted.Match.Value, "raw values keep partial-mask semantics")
	encoded := redactionVariants(t, secret)
	assert.Equal(t, "token="+MaskSecret(secret, 50)+" b64=REDACTED", redacted.Match.Full)
	assert.Equal(t, "REDACTED", redacted.Match.Captures["encoded"])
	assert.Equal(t, "prefix[redacted]suffix", redacted.Analysis.StatusMetadata["embedded"],
		"encoded equivalents inside surrounding text are fully masked")
	assert.Equal(t, "payload [redacted]", redacted.Analysis.Metadata["echo"])
	assert.NotContains(t, redacted.Match.Line, encoded["query"])
	assert.NotContains(t, redacted.Match.Context, encoded["raw url base64"])
}

func TestRedactLongestVariantWins(t *testing.T) {
	short := "abc"
	long := "abcdef"
	finding := Finding{
		Match: Match{
			Full:  long + " " + short,
			Value: long,
			Line:  "b64 " + base64.StdEncoding.EncodeToString([]byte(long)) + " " + short,
			Captures: map[string]string{
				"long":  long,
				"short": short,
			},
		},
		Analysis: Analysis{
			Reason: long + " " + short,
			Metadata: map[string]any{
				"long_b64": base64.StdEncoding.EncodeToString([]byte(long)),
			},
		},
	}
	finding.Redact(100)

	assert.Equal(t, "REDACTED REDACTED", finding.Match.Full)
	// The base64 form of the longer secret is replaced as a whole; no encoded
	// equivalent of either credential may remain visible in the snippet.
	assert.NotContains(t, finding.Match.Line, base64.StdEncoding.EncodeToString([]byte(long)))
	assert.NotContains(t, finding.Match.Line, base64.RawStdEncoding.EncodeToString([]byte(long)))
	assert.NotContains(t, finding.Match.Line, long)
	assert.NotContains(t, finding.Match.Line, short)
	assert.Equal(t, "REDACTED", finding.Match.Captures["long"])
	assert.Equal(t, "REDACTED", finding.Match.Captures["short"])
	assert.Equal(t, "[redacted] [redacted]", finding.Analysis.Reason)
	assert.Equal(t, "[redacted]", finding.Analysis.Metadata["long_b64"])
}

func TestRedactOverlappingEncodedVariantsUseLongestMatch(t *testing.T) {
	short := "abc"
	long := "abcdef"
	shortB64 := base64.StdEncoding.EncodeToString([]byte(short))
	longB64 := base64.StdEncoding.EncodeToString([]byte(long))
	finding := Finding{
		Match: Match{
			Full:  longB64 + " " + shortB64,
			Value: long,
			Captures: map[string]string{
				"long":  longB64,
				"short": shortB64,
			},
		},
		Analysis: Analysis{Reason: longB64 + " " + shortB64},
	}
	finding.Redact(100)

	assert.Equal(t, "REDACTED REDACTED", finding.Match.Full, "the longer encoded equivalent must win on overlap")
	assert.Equal(t, "REDACTED", finding.Match.Captures["long"])
	assert.Equal(t, "REDACTED", finding.Match.Captures["short"])
	assert.Equal(t, "[redacted] [redacted]", finding.Analysis.Reason)
}

func TestRedactedCopyEncodedVariantsDoNotMutateOriginal(t *testing.T) {
	const secret = "rotate-me-please-123"
	original := variantFinding(t, secret)
	before, err := json.Marshal(original)
	require.NoError(t, err)

	redacted := original.RedactedCopy(75)
	redactedData, err := json.Marshal(redacted)
	require.NoError(t, err)
	assertNoVariantLeak(t, secret, string(redactedData))

	after, err := json.Marshal(original)
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "redaction must not mutate the original finding")
	assert.Equal(t, secret, original.Match.Value)
	assert.Equal(t, secret, original.ComponentSets[0].Components[0].Match.Value)

	variants := redactionVariants(t, secret)
	assert.Equal(t, variants["base64"], original.Match.Captures["encoded"])
	assert.Equal(t, "line token="+variants["query"]+" and "+variants["json"], original.Match.Line)
	assert.Equal(t, "payload "+variants["raw base64"], original.Analysis.Metadata["echo"])
}

func TestSanitizeAnalysisCoversEncodedEquivalents(t *testing.T) {
	const secret = "analysis-secret-42"
	variants := redactionVariants(t, secret)
	analysis := Analysis{
		StatusReason:   "url " + variants["query"],
		StatusMetadata: map[string]any{"b64": variants["base64"]},
		Reason:         "json " + variants["json"],
		Metadata:       map[string]any{"raw": variants["raw url base64"], "nested": map[string]any{"v": variants["raw base64"]}},
		Debug:          map[string]any{"body": "x" + variants["path"] + "y"},
		Identity:       &AnalysisIdentity{Email: "e-" + variants["base64"] + "@example.invalid"},
	}

	sanitized := SanitizeAnalysis(analysis, []string{secret})
	data, err := json.Marshal(sanitized)
	require.NoError(t, err)
	assertNoVariantLeak(t, secret, string(data))
	assert.Equal(t, "x[redacted]y", sanitized.Debug["body"])

	// Sanitization must not mutate the caller's analysis.
	assert.Equal(t, "url "+variants["query"], analysis.StatusReason)
	assert.Equal(t, variants["base64"], analysis.StatusMetadata["b64"])
}

func TestCredentialReportCoversEncodedEquivalents(t *testing.T) {
	const secret = "credential-channel-secret"
	variants := redactionVariants(t, secret)
	finding := Finding{
		RuleID: "rule",
		Analysis: Analysis{
			Status: ValidationStatusValid,
			Reason: variants["query"],
			Metadata: map[string]any{
				"b64":  variants["base64"],
				"json": map[string]string{"token": variants["json"]},
			},
			Debug: map[string]any{"req": variants["raw base64"]},
		},
		ComponentSets: []ComponentSet{{
			Analysis: Analysis{Status: ValidationStatusValid, Reason: variants["path"]},
			Components: []ComponentFinding{{
				RuleID: "part",
				Match:  Match{Value: secret, Captures: map[string]string{"token": variants["url base64"]}},
			}},
		}},
	}

	result := NewCredentialReport(finding, finding.CredentialValues())

	for _, format := range []CredentialReportFormat{CredentialReportFormatJSONL, CredentialReportFormatPretty} {
		var output strings.Builder
		require.NoError(t, (CredentialReporter{Format: format, NoColor: true}).Write(&output, result))
		assertNoVariantLeak(t, secret, output.String())
	}
}

func TestJSONAndJSONLChannelsCoverEncodedEquivalents(t *testing.T) {
	const secret = "channel-secret-9876543210"
	original := variantFinding(t, secret)
	original.Match.Fingerprint = "fp-primary"
	original.ComponentSets[0].Components[0].Match.Fingerprint = "fp-component"

	for _, percent := range []uint{50, 100} {
		redacted := original.RedactedCopy(percent)
		for name, write := range map[string]func(*strings.Builder) error{
			"json": func(builder *strings.Builder) error {
				return WriteJSON(builder, []Finding{redacted})
			},
			"jsonl": func(builder *strings.Builder) error {
				return WriteJSONL(builder, []Finding{redacted})
			},
		} {
			t.Run(name, func(t *testing.T) {
				var output strings.Builder
				require.NoError(t, write(&output))
				assertNoVariantLeak(t, secret, output.String())
				assert.Contains(t, output.String(), "fp-primary")
			})
		}
	}

	var pretty strings.Builder
	require.NoError(t, WritePretty(&pretty, original, PrettyOptions{NoColor: true, Redact: 100, Width: 100}))
	assertNoVariantLeak(t, secret, pretty.String())
}

func TestRedactVariantEdgeCases(t *testing.T) {
	t.Run("empty and short values keep existing semantics", func(t *testing.T) {
		finding := Finding{Match: Match{Full: "x ss y", Value: "ss", Captures: map[string]string{"empty": ""}}}
		finding.Redact(75)
		assert.Equal(t, "...", finding.Match.Value, "short-string semantics are preserved")
		assert.Equal(t, "x ... y", finding.Match.Full)
		assert.Empty(t, credentialSecretVariants(""))
		assert.Empty(t, credentialEncodedSecretsForRedaction(nil))
	})

	t.Run("encoding identical to raw keeps partial masking", func(t *testing.T) {
		const simple = "abc123"
		finding := Finding{Match: Match{Full: "v=" + simple, Value: simple}}
		finding.Redact(50)
		assert.Equal(t, MaskSecret(simple, 50), finding.Match.Value)
		assert.Contains(t, finding.Match.Full, MaskSecret(simple, 50))
	})

	t.Run("base64 embedded in analysis metadata is fully redacted", func(t *testing.T) {
		const secret = "embed-this-token-value"
		encoded := base64.StdEncoding.EncodeToString([]byte(secret))
		finding := Finding{
			Match:    Match{Value: secret},
			Analysis: Analysis{Metadata: map[string]any{"url": "https://x.test/?d=" + encoded + "&n=1"}},
		}
		redacted := finding.RedactedCopy(100)
		data, err := json.Marshal(redacted.Analysis)
		require.NoError(t, err)
		assert.NotContains(t, string(data), encoded)
		assert.NotContains(t, string(data), secret)
	})
}
