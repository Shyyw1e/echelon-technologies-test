package analyser

import (
	"os"
	"sort"
)

type Analyzer struct {
	rules []Rule
}

func NewDefault() Analyzer {
	return Analyzer{
		rules: []Rule{
			DebugLoggingRule{},
			PlaintextSecretRule{},
			WildcardBindRule{},
			DisabledTLSRule{},
			WeakAlgorithmRule{},
			FilePermissionRule{},
		},
	}
}

func (a Analyzer) Analyze(data []byte, metadata Metadata) ([]Issue, error) {
	root, err := ParseConfig(data)
	if err != nil {
		return nil, err
	}

	doc := Document{Root: root, Metadata: metadata}
	issues := make([]Issue, 0)
	for _, rule := range a.rules {
		issues = append(issues, rule.Check(doc)...)
	}

	for index := range issues {
		if issues[index].Source == "" {
			issues[index].Source = metadata.SourcePath
		}
	}

	sortIssues(issues)
	return issues, nil
}

func MetadataFromFile(path string) Metadata {
	info, err := os.Stat(path)
	if err != nil {
		return Metadata{SourcePath: path}
	}

	return Metadata{
		SourcePath: path,
		FileMode:   uint32(info.Mode().Perm()),
		HasMode:    true,
	}
}

func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, j int) bool {
		if severityRank(issues[i].Severity) != severityRank(issues[j].Severity) {
			return severityRank(issues[i].Severity) > severityRank(issues[j].Severity)
		}
		if issues[i].Source != issues[j].Source {
			return issues[i].Source < issues[j].Source
		}
		return issues[i].Path < issues[j].Path
	})
}

func severityRank(severity Severity) int {
	switch severity {
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}
