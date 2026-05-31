package analyser

import "testing"

func TestAnalyzerFindsConfiguredIssues(t *testing.T) {
	t.Parallel()

	config := []byte(`
log:
  level: debug
database:
  password: plain-text-password
storage:
  digest-algorithm: MD5
client:
  insecure_skip_verify: true
server:
  host: 0.0.0.0
`)

	issues, err := NewDefault().Analyze(config, Metadata{SourcePath: "test.yaml"})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	wantRules := map[string]bool{
		"debug_logging":    false,
		"plaintext_secret": false,
		"weak_algorithm":   false,
		"disabled_tls":     false,
		"wildcard_bind":    false,
	}
	for _, issue := range issues {
		if _, ok := wantRules[issue.RuleID]; ok {
			wantRules[issue.RuleID] = true
		}
	}

	for rule, found := range wantRules {
		if !found {
			t.Fatalf("expected issue for rule %s, got %#v", rule, issues)
		}
	}
}

func TestAnalyzerIgnoresEnvSecretReferences(t *testing.T) {
	t.Parallel()

	config := []byte(`
database:
  password: ${DB_PASSWORD}
service:
  api_key: env:SERVICE_API_KEY
`)

	issues, err := NewDefault().Analyze(config, Metadata{SourcePath: "test.yaml"})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	for _, issue := range issues {
		if issue.RuleID == "plaintext_secret" {
			t.Fatalf("did not expect plaintext secret issue for env reference: %#v", issues)
		}
	}
}

func TestAnalyzerReportsFilePermissions(t *testing.T) {
	t.Parallel()

	issues, err := NewDefault().Analyze([]byte(`version: 1`), Metadata{
		SourcePath: "config.yaml",
		FileMode:   0o666,
		HasMode:    true,
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if len(issues) != 1 {
		t.Fatalf("expected one issue, got %#v", issues)
	}
	if issues[0].RuleID != "file_permissions" || issues[0].Severity != SeverityHigh {
		t.Fatalf("unexpected permission issue: %#v", issues[0])
	}
}
