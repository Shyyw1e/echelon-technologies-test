package analyser

import "testing"

func TestWildcardBindAllowsExplicitRestrictions(t *testing.T) {
	t.Parallel()

	config := []byte(`
server:
  host: 0.0.0.0
network:
  allowlist:
    - 10.0.0.0/8
`)

	issues, err := NewDefault().Analyze(config, Metadata{SourcePath: "restricted.yaml"})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	for _, issue := range issues {
		if issue.RuleID == "wildcard_bind" {
			t.Fatalf("did not expect wildcard issue when allowlist exists: %#v", issues)
		}
	}
}

func TestFilePermissionRuleAllowsRestrictiveMode(t *testing.T) {
	t.Parallel()

	issues, err := NewDefault().Analyze([]byte(`version: 1`), Metadata{
		SourcePath: "config.yaml",
		FileMode:   0o600,
		HasMode:    true,
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	for _, issue := range issues {
		if issue.RuleID == "file_permissions" {
			t.Fatalf("did not expect file permission issue: %#v", issues)
		}
	}
}

func TestFilePermissionRuleReportsGroupOrOtherAccess(t *testing.T) {
	t.Parallel()

	issues, err := NewDefault().Analyze([]byte(`version: 1`), Metadata{
		SourcePath: "config.yaml",
		FileMode:   0o644,
		HasMode:    true,
	})
	if err != nil {
		t.Fatalf("Analyze() error = %v", err)
	}

	if len(issues) != 1 {
		t.Fatalf("expected one issue, got %#v", issues)
	}
	if issues[0].RuleID != "file_permissions" || issues[0].Severity != SeverityMedium {
		t.Fatalf("unexpected issue: %#v", issues[0])
	}
}
