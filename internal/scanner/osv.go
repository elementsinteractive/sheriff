package scanner

import (
	"encoding/json"
	"path/filepath"
	"sheriff/internal/shell"
	"strconv"
	"time"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
	gogitlab "github.com/xanzy/go-gitlab"
)

type osvReferenceKind string

const (
	OsvCommandName                  = "osv-scanner"
	AdvisoryKind   osvReferenceKind = "ADVISORY"
	WebKind        osvReferenceKind = "WEB"
	PackageKind    osvReferenceKind = "PACKAGE"
	osvTimeout                      = 30 * time.Second
)

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvReference struct {
	Type osvReferenceKind `json:"type"`
	Url  string           `json:"url"`
}

type osvDatabaseSpecific struct {
	Severity string `json:"severity"`
}

type osvEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
}

type osvRange struct {
	Events []osvEvent `json:"events"`
}

type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

// osvVulnerability represents a vulnerability as defined by the OSV schema.
type osvVulnerability struct {
	Id               string              `json:"id"`                // Unique identifier for the vulnerability.
	Aliases          []string            `json:"aliases"`           // Alternative identifiers for the vulnerability.
	Summary          string              `json:"summary"`           // Short summary of the vulnerability.
	Detail           string              `json:"detail"`            // Detailed description of the vulnerability.
	Version          string              `json:"schema_version"`    // Schema version used.
	References       []osvReference      `json:"references"`        // References related to the vulnerability.
	DatabaseSpecific osvDatabaseSpecific `json:"database_specific"` // Database-specific information.
	Affected         []osvAffected       `json:"affected"`          // List of affected packages.
}

// osvGroup represents a group of vulnerabilities.
type osvGroup struct {
	Ids         []string `json:"ids"`          // List of vulnerability IDs in the group.
	Aliases     []string `json:"aliases"`      // Alternative identifiers for the group.
	MaxSeverity string   `json:"max_severity"` // Maximum severity of the vulnerabilities in the group.
}

// osvPackageInfo contains information about a package.
type osvPackageInfo struct {
	Name      string `json:"name"`      // Name of the package.
	Version   string `json:"version"`   // Version of the package.
	Ecosystem string `json:"ecosystem"` // Ecosystem to which the package belongs.
}

// osvPackage represents a package and its associated vulnerabilities and groups.
type osvPackage struct {
	PackageInfo     osvPackageInfo     `json:"package"`         // Information about the package.
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"` // List of vulnerabilities associated with the package.
	Groups          []osvGroup         `json:"groups"`          // List of groups associated with the package.
}

// osvResult represents the result of a vulnerability scan.
type osvResult struct {
	Source   osvSource    `json:"source"`   // Source of the vulnerability information.
	Packages []osvPackage `json:"packages"` // List of packages in the result.
}

// OsvReport represents a vulnerability report as returned by osv-scanner.
type OsvReport struct {
	Results []osvResult `json:"results"` // List of results in the report.
}

// osvScanner is a concrete implementation of the VulnScanner interface
// that uses Google's osv-scanner to scan for vulnerabilities in a project directory.
type osvScanner struct{}

// NewOsvScanner creates a new instance of osvScanner.
// It is a vulnScanner that uses Google's osv-scanner to scan for vulnerabilities.
func NewOsvScanner() VulnScanner[OsvReport] {
	return &osvScanner{}
}

// Scan scans the specified directory for vulnerabilities using osv-scanner.
func (s *osvScanner) Scan(dir string) (*OsvReport, error) {
	var report *OsvReport

	cmdOut, err := shell.ShellCommandRunner.Run(
		shell.CommandInput{
			Name:    OsvCommandName,
			Args:    []string{"-r", "--verbosity", "error", "--format", "json", dir},
			Timeout: osvTimeout,
		},
	)

	//Handle exit codes according to https://google.github.io/osv-scanner/output/#return-codes
	if cmdOut.ExitCode == 0 && err == nil {
		// Successful run of osv-scanner, no report because no vulnerabilities found
		log.Debug().Int("exitCode", cmdOut.ExitCode).Msg("osv-scanner did not find vulnerabilities")
		return nil, nil
	} else if cmdOut.ExitCode > 1 || cmdOut.ExitCode == -1 {
		// Failed to run osv-scanner at all, or it returned an error
		log.Debug().Int("exitCode", cmdOut.ExitCode).Msg("osv-scanner failed to run")
		return nil, err
	}
	// Error code 1, osv-scanner ran successfully and found vulnerabilities
	log.Debug().Msg("osv-scanner ran successfully; found vulnerabilities")
	report, err = readOSVJson(cmdOut.Output)
	if err != nil {
		return report, err
	}

	return report, nil
}

// GenerateReport generates a Report struct from the OsvReport.
func (s *osvScanner) GenerateReport(p gogitlab.Project, r *OsvReport) Report {
	if r == nil {
		return Report{
			Project:         p,
			IsVulnerable:    false,
			Vulnerabilities: []Vulnerability{},
		}
	}

	var vs []Vulnerability
	for _, p := range r.Results {
		for _, pkg := range p.Packages {
			for _, v := range pkg.Vulnerabilities {
				packageRef := pie.FirstOr(pie.Filter(v.References, func(ref osvReference) bool { return ref.Type == PackageKind }), osvReference{})
				source := filepath.Base(p.Source.Path)
				sevIdx := pie.FindFirstUsing(pkg.Groups, func(g osvGroup) bool { return pie.Contains(g.Ids, v.Id) || pie.Contains(g.Aliases, v.Id) })
				var severity string
				if sevIdx != -1 {
					severity = pkg.Groups[sevIdx].MaxSeverity
				} else {
					severity = ""
				}

				vs = append(vs, Vulnerability{
					Id:                v.Id,
					PackageName:       pkg.PackageInfo.Name,
					PackageVersion:    pkg.PackageInfo.Version,
					PackageUrl:        packageRef.Url,
					PackageEcosystem:  pkg.PackageInfo.Ecosystem,
					Source:            source,
					Severity:          severity,
					SeverityScoreKind: getSeverityScoreKind(severity),
					Summary:           v.Summary,
					Details:           v.Detail,
					FixAvailable:      hasFixAvailable(v),
				})
			}
		}
	}

	return Report{
		Project:         p,
		IsVulnerable:    len(vs) > 0,
		Vulnerabilities: vs,
	}
}

// readOSVJson reads the JSON output from osv-scanner
// and returns a Report struct with the results
func readOSVJson(data []byte) (report *OsvReport, err error) {
	err = json.Unmarshal(data, &report)
	return
}

// getSeverityScoreKind returns the SeverityScoreKind based on the severity score from OSV
func getSeverityScoreKind(severity string) SeverityScoreKind {
	if severity == "" {
		log.Debug().Msg("Severity is empty, defaulting to Unknown")
		return Unknown
	}
	floatSeverity, err := strconv.ParseFloat(severity, 32)
	if err != nil {
		log.Warn().Str("severity", severity).Msg("Failed to parse severity to float, defaulting to Unknown")
		return Unknown
	}

	maxKind := Unknown
	for k, v := range SeverityScoreThresholds {
		if floatSeverity >= v && v >= SeverityScoreThresholds[maxKind] {
			maxKind = k
		}
	}
	return maxKind
}

// hasFixAvailable returns true if the vulnerability has at least one version that is not vulnerable
func hasFixAvailable(v osvVulnerability) bool {
	// If there is any version with a fixed event, then the vulnerability has at least one version
	// that is not vulnerable
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return true
				}
			}
		}
	}
	return false
}
