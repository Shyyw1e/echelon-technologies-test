package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunStdinReturnsErrorWhenIssuesFound(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(
		[]string{"--stdin"},
		strings.NewReader(`{"log":{"level":"debug"}}`),
		&stdout,
		&stderr,
	)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if !strings.Contains(stdout.String(), "LOW") {
		t.Fatalf("expected issue output, got %q", stdout.String())
	}
}

func TestRunSilentKeepsZeroExitCode(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(
		[]string{"--stdin", "--silent"},
		strings.NewReader(`{"log":{"level":"debug"}}`),
		&stdout,
		&stderr,
	)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr=%q", code, stderr.String())
	}
}

func TestRunAnalyzesFile(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("storage:\n  digest-algorithm: MD5\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(
		[]string{"--silent", path},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "weak_algorithm") {
		t.Fatalf("expected weak algorithm issue, got %q", stdout.String())
	}
}

func TestRunAnalyzesDirectoryRecursively(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "config.json"), []byte(`{"log":{"level":"debug"}}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "notes.txt"), []byte(`{"log":{"level":"debug"}}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(
		[]string{"--dir", root, "--silent"},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr=%q", code, stderr.String())
	}
	if count := strings.Count(stdout.String(), "debug_logging"); count != 1 {
		t.Fatalf("expected one debug issue, got %d in %q", count, stdout.String())
	}
}

func TestRunJSONOutput(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(
		[]string{"--stdin", "--silent", "--format", "json"},
		strings.NewReader(`{"log":{"level":"debug"}}`),
		&stdout,
		&stderr,
	)

	if code != 0 {
		t.Fatalf("expected exit code 0, got %d; stderr=%q", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"issues"`) || !strings.Contains(stdout.String(), `"debug_logging"`) {
		t.Fatalf("expected json issues output, got %q", stdout.String())
	}
}

func TestRunReturnsUsageErrorWithoutInput(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(nil, strings.NewReader(""), &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunRejectsInvalidModeCombination(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(
		[]string{"--stdin", "--dir", "."},
		strings.NewReader(""),
		&stdout,
		&stderr,
	)

	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRunRejectsTooLargeStdin(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(
		[]string{"--stdin", "--max-size", "4"},
		strings.NewReader("version: 1"),
		&stdout,
		&stderr,
	)

	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}
