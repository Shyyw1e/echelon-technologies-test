package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Shyyw1e/echelon-technologies-test/internal/analyser"
	"github.com/Shyyw1e/echelon-technologies-test/internal/grpcapi"
	"github.com/Shyyw1e/echelon-technologies-test/internal/httpapi"
)

const (
	defaultHTTPAddr       = ":8080"
	defaultGRPCAddr       = ":9090"
	defaultMaxConfigBytes = int64(1 << 20)
	defaultOutputFormat   = "text"
)

type options struct {
	silent         bool
	stdin          bool
	dir            string
	http           string
	grpc           string
	format         string
	maxConfigBytes int64
}

func Run(args []string, stdin io.Reader, stdout io.Writer, stderr io.Writer) int {
	opts, positional, err := parseArgs(args)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	a := analyser.NewDefault()

	switch {
	case opts.http != "":
		if err := httpapi.ListenAndServe(opts.http, a, opts.maxConfigBytes); err != nil {
			fmt.Fprintf(stderr, "http server failed: %v\n", err)
			return 1
		}
		return 0
	case opts.grpc != "":
		if err := grpcapi.ListenAndServe(opts.grpc, a, opts.maxConfigBytes); err != nil {
			fmt.Fprintf(stderr, "grpc server failed: %v\n", err)
			return 1
		}
		return 0
	case opts.dir != "":
		issues, err := analyzeDir(opts.dir, a)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return finish(stdout, stderr, opts, issues)
	case opts.stdin:
		data, err := io.ReadAll(io.LimitReader(stdin, opts.maxConfigBytes+1))
		if err != nil {
			fmt.Fprintf(stderr, "read stdin: %v\n", err)
			return 1
		}
		if int64(len(data)) > opts.maxConfigBytes {
			fmt.Fprintf(stderr, "stdin config exceeds %d bytes\n", opts.maxConfigBytes)
			return 1
		}

		issues, err := a.Analyze(data, analyser.Metadata{SourcePath: "stdin"})
		if err != nil {
			fmt.Fprintf(stderr, "analyze stdin: %v\n", err)
			return 1
		}
		return finish(stdout, stderr, opts, issues)
	default:
		if len(positional) != 1 {
			fmt.Fprintln(stderr, "usage: config-audit [flags] <file>")
			return 2
		}

		issues, err := analyzeFile(positional[0], a)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return finish(stdout, stderr, opts, issues)
	}
}

func parseArgs(args []string) (options, []string, error) {
	opts := options{
		format:         defaultOutputFormat,
		maxConfigBytes: defaultMaxConfigBytes,
	}
	flags := flag.NewFlagSet("config-audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&opts.silent, "s", false, "do not return non-zero code when issues are found")
	flags.BoolVar(&opts.silent, "silent", false, "do not return non-zero code when issues are found")
	flags.BoolVar(&opts.stdin, "stdin", false, "read config from stdin")
	flags.StringVar(&opts.dir, "dir", "", "recursively analyze configs in directory")
	flags.StringVar(&opts.http, "http", "", "run REST API server on address")
	flags.StringVar(&opts.grpc, "grpc", "", "run gRPC server on address")
	flags.StringVar(&opts.format, "format", defaultOutputFormat, "output format: text or json")
	flags.Int64Var(&opts.maxConfigBytes, "max-size", defaultMaxConfigBytes, "maximum config size in bytes")

	if err := flags.Parse(args); err != nil {
		return opts, nil, err
	}

	if opts.http == "" && hasFlag(args, "--http") {
		opts.http = defaultHTTPAddr
	}
	if opts.grpc == "" && hasFlag(args, "--grpc") {
		opts.grpc = defaultGRPCAddr
	}

	return opts, flags.Args(), validateMode(opts)
}

func validateMode(opts options) error {
	modes := 0
	for _, enabled := range []bool{opts.stdin, opts.dir != "", opts.http != "", opts.grpc != ""} {
		if enabled {
			modes++
		}
	}
	if modes > 1 {
		return errors.New("choose only one mode: --stdin, --dir, --http or --grpc")
	}
	if opts.format != "text" && opts.format != "json" {
		return errors.New("unsupported --format, expected text or json")
	}
	if opts.maxConfigBytes <= 0 {
		return errors.New("--max-size must be greater than zero")
	}
	return nil
}

func hasFlag(args []string, name string) bool {
	for _, arg := range args {
		if arg == name {
			return true
		}
	}
	return false
}

func analyzeFile(path string, a analyser.Analyzer) ([]analyser.Issue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	issues, err := a.Analyze(data, analyser.MetadataFromFile(path))
	if err != nil {
		return nil, fmt.Errorf("analyze %s: %w", path, err)
	}
	return issues, nil
}

func analyzeDir(root string, a analyser.Analyzer) ([]analyser.Issue, error) {
	var all []analyser.Issue
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !isConfigFile(path) {
			return nil
		}

		issues, err := analyzeFile(path, a)
		if err != nil {
			return err
		}
		all = append(all, issues...)
		return nil
	})
	return all, err
}

func isConfigFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json", ".yaml", ".yml":
		return true
	default:
		return false
	}
}

func finish(stdout io.Writer, stderr io.Writer, opts options, issues []analyser.Issue) int {
	if opts.format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		_ = encoder.Encode(map[string]any{"issues": issues})
	} else {
		printText(stdout, issues)
	}

	if len(issues) > 0 && !opts.silent {
		fmt.Fprintf(stderr, "found %d issue(s)\n", len(issues))
		return 1
	}
	return 0
}

func printText(writer io.Writer, issues []analyser.Issue) {
	if len(issues) == 0 {
		fmt.Fprintln(writer, "No issues found.")
		return
	}

	for _, issue := range issues {
		location := issue.Path
		if issue.Source != "" {
			location = issue.Source
			if issue.Path != "" {
				location += ":" + issue.Path
			}
		}

		fmt.Fprintf(writer, "%s: %s\n", issue.Severity, issue.Message)
		if location != "" {
			fmt.Fprintf(writer, "  location: %s\n", location)
		}
		fmt.Fprintf(writer, "  rule: %s\n", issue.RuleID)
		fmt.Fprintf(writer, "  recommendation: %s\n", issue.Recommendation)
	}
}
