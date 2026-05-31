package analyser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConfigSupportsJSONAndYAML(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "json", data: []byte(`{"log":{"level":"debug"}}`)},
		{name: "yaml", data: []byte("log:\n  level: debug\n")},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root, err := ParseConfig(tt.data)
			if err != nil {
				t.Fatalf("ParseConfig() error = %v", err)
			}

			if _, ok := root["log"]; !ok {
				t.Fatalf("expected log key in %#v", root)
			}
		})
	}
}

func TestParseConfigRejectsInvalidOrNonObjectRoot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{name: "invalid", data: []byte(":\n  bad")},
		{name: "array root", data: []byte("- debug\n- trace\n")},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := ParseConfig(tt.data); err == nil {
				t.Fatal("expected ParseConfig() error")
			}
		})
	}
}

func TestWalkIncludesArrayIndexes(t *testing.T) {
	t.Parallel()

	root := map[string]any{
		"servers": []any{
			map[string]any{"host": "0.0.0.0"},
		},
	}

	nodes := Walk(root)
	for _, node := range nodes {
		if node.Path == "servers[0].host" {
			return
		}
	}

	t.Fatalf("expected array path in nodes: %#v", nodes)
}

func TestMetadataFromFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("version: 1"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	meta := MetadataFromFile(path)
	if meta.SourcePath != path {
		t.Fatalf("SourcePath = %q, want %q", meta.SourcePath, path)
	}
	if !meta.HasMode {
		t.Fatal("expected HasMode")
	}
	if meta.FileMode&0o777 == 0 {
		t.Fatalf("expected file mode, got %o", meta.FileMode)
	}
}

func TestMetadataFromFileWhenStatFails(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing.yaml")
	meta := MetadataFromFile(path)
	if meta.SourcePath != path {
		t.Fatalf("SourcePath = %q, want %q", meta.SourcePath, path)
	}
	if meta.HasMode {
		t.Fatal("did not expect HasMode for missing file")
	}
}
