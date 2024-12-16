// Package scanner provides vulnerability scanners with a common interface.
package scanner

import (
	"sheriff/internal/config"

	gogitlab "github.com/xanzy/go-gitlab"
)

type SeverityScoreKind string

const (
	Critical     SeverityScoreKind = "CRITICAL"
	High         SeverityScoreKind = "HIGH"
	Moderate     SeverityScoreKind = "MODERATE"
	Low          SeverityScoreKind = "LOW"
	Unknown      SeverityScoreKind = "UNKNOWN"
	Acknowledged SeverityScoreKind = "ACKNOWLEDGED"
)

// SeverityScoreThresholds are inferred from CSVSS reports we've seen in the wild.
// The value represents the lower bound (inclusive) of the severity score kind.
// They may need to be adjusted as we observe more vulnerabilities.
var SeverityScoreThresholds = map[SeverityScoreKind]float64{
	Critical:     9.0,
	High:         8.0,
	Moderate:     3.0,
	Low:          0.0,
	Unknown:      -1.0, // Arbitrary value to represent unknown severity
	Acknowledged: -2.0, // Arbitrary value to represent acknowledged vulnerabilities
}

// Vulnerability is a representation of what a vulnerability is within our scanner
type Vulnerability struct {
	Id                string
	PackageName       string
	PackageVersion    string
	PackageUrl        string
	PackageEcosystem  string
	Source            string
	Severity          string
	SeverityScoreKind SeverityScoreKind
	Summary           string
	Details           string
	FixAvailable      bool
	AckReason         string // Optional reason for acknowledging the vulnerability
}

// Report is the main report representation of a project vulnerability scan.
type Report struct {
	Project         gogitlab.Project
	ProjectConfig   config.ProjectConfig // Contains the project-level configuration that users of sheriff may have in their repository
	IsVulnerable    bool
	Vulnerabilities []Vulnerability
	IssueUrl        string // URL of the GitLab issue. Conditionally set if --gitlab-issue is passed
	Error           bool   // Conditionally set if an error occurred during the scan
}

// VulnScanner is an interface for any vulnerability scanner
type VulnScanner[T any] interface {
	// Scan runs a vulnerability scan on the given directory
	Scan(dir string) (*T, error)
	// GenerateReport maps the report from the scanner to our internal representation of vulnerability reports.
	GenerateReport(p gogitlab.Project, r *T) Report
}
