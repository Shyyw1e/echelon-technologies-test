package analyser

type Severity string

const (
	SeverityLow    Severity = "LOW"
	SeverityMedium Severity = "MEDIUM"
	SeverityHigh   Severity = "HIGH"
)

type Issue struct {
	Severity       Severity `json:"severity"`
	RuleID         string   `json:"rule"`
	Message        string   `json:"message"`
	Recommendation string   `json:"recommendation"`
	Path           string   `json:"path,omitempty"`
	Source         string   `json:"source,omitempty"`
}

type Metadata struct {
	SourcePath string
	FileMode   uint32
	HasMode    bool
}

type Document struct {
	Root     map[string]any
	Metadata Metadata
}

type Rule interface {
	ID() string
	Check(Document) []Issue
}
