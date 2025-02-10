package publish

import (
	"errors"
	"fmt"
	"sheriff/internal/repository/provider"
	"sheriff/internal/scanner"
	"strconv"
	"sync"
	"time"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
)

// severityScoreOrder represents the order of SeverityScoreKind by their score in descending order
// which is how we want to display it in the Issue report
var severityScoreOrder = getSeverityScoreOrder(scanner.SeverityScoreThresholds)

// now is a function that returns the current time
var now = time.Now

// PublishAsIssues creates or updates Issue reports for the given reports
// It will add the Issue URL to the Report if it was created or updated successfully
func PublishAsIssues(reports []scanner.Report, s provider.IProvider) (warn error) {
	var wg sync.WaitGroup
	for i := 0; i < len(reports); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			report := reports[i]
			if report.IsVulnerable {
				if issue, err := s.Provide(report.Project.Repository).OpenVulnerabilityIssue(report.Project, formatIssue(report)); err != nil {
					log.Error().Err(err).Str("project", reports[i].Project.Path).Msg("Failed to open or update issue")
					err = fmt.Errorf("failed to open or update issue for project %v", reports[i].Project.Path)
					warn = errors.Join(err, warn)
				} else {
					reports[i].IssueUrl = issue.WebURL
				}
			} else {
				if err := s.Provide(report.Project.Repository).CloseVulnerabilityIssue(report.Project); err != nil {
					log.Error().Err(err).Str("project", report.Project.Path).Msg("Failed to close issue")
					err = fmt.Errorf("failed to close issue for project %v", report.Project.Path)
					warn = errors.Join(err, warn)
				}
			}
		}()
	}
	wg.Wait()

	return
}

// severityBiggerThan compares two CVSS scores and returns true if a is bigger than b
// It will fallback to string comparison if it fails to parse the CVSS scores
func severityBiggerThan(a string, b string) bool {
	aFloat, errA := strconv.ParseFloat(a, 32)
	bFloat, errB := strconv.ParseFloat(b, 32)
	if errA != nil || errB != nil {
		log.Warn().Str("a", a).Str("b", b).Msg("Failed to parse vulnerability CVSS to float, defaulting to string comparison")
		return a > b
	}
	return aFloat > bFloat
}

// groupVulnReportsByMaxSeverityKind groups the reports by the maximum severity kind of the vulnerabilities
func groupVulnReportsByMaxSeverityKind(reports []scanner.Report) map[scanner.SeverityScoreKind][]scanner.Report {
	vulnerableReports := pie.Filter(reports, func(r scanner.Report) bool { return r.IsVulnerable })
	groupedVulnerabilities := pie.GroupBy(vulnerableReports, func(r scanner.Report) scanner.SeverityScoreKind {
		maxSeverity := pie.SortUsing(r.Vulnerabilities, func(a, b scanner.Vulnerability) bool {
			return scanner.SeverityScoreThresholds[a.SeverityScoreKind] > scanner.SeverityScoreThresholds[b.SeverityScoreKind]
		})[0]

		return maxSeverity.SeverityScoreKind
	})

	return groupedVulnerabilities
}

// formatIssue formats the report as an issue
func formatIssue(r scanner.Report) (mdReport string) {
	groupedVulnerabilities := pie.GroupBy(r.Vulnerabilities, func(v scanner.Vulnerability) scanner.SeverityScoreKind { return v.SeverityScoreKind })

	mdReport = getVulnReportHeader()
	for _, groupName := range severityScoreOrder {
		if group, ok := groupedVulnerabilities[groupName]; ok {
			sortedVulnsInGroup := pie.SortUsing(group, func(a, b scanner.Vulnerability) bool {
				return severityBiggerThan(a.Severity, b.Severity)
			})
			mdReport += formatIssueTable(groupName, sortedVulnsInGroup)
		}
	}

	// Add outdated acknowledgements section
	mdReport += formatOutdatedAcks(r.OutdatedAcks)

	return
}

// formatOutdatedAcks formats the outdated acknowledgements as a markdown section
func formatOutdatedAcks(outdatedAcks []string) (md string) {
	if len(outdatedAcks) == 0 {
		return
	}

	md = "\n\n-------\n\n### Outdated Acknowledgements\n"
	md += "\n💡 These vulnerabilities were acknowledged in the project configuration but are no longer relevant.\n\n"
	for _, ack := range outdatedAcks {
		md += fmt.Sprintf("- `%v`\n", ack)
	}
	return
}

// formatIssueTable formats a group of vulnerabilities as a markdown table
// for the issue report
func formatIssueTable(groupName scanner.SeverityScoreKind, vs []scanner.Vulnerability) (md string) {
	md = fmt.Sprintf("\n## Severity: %v\n", groupName)
	if groupName == scanner.Acknowledged {
		md += "\n💡 These vulnerabilities have been acknowledged by the team and are not considered a risk.\n\n"
		// Acknowledge vulnerabilities have an extra `Reason` column
		md += "| OSV URL | CVSS | Ecosystem | Package | Version | Fix Available | Reason | Source |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n"
	} else {
		md += "| OSV URL | CVSS | Ecosystem | Package | Version | Fix Available | Source |\n| --- | --- | --- | --- | --- | --- | --- |\n"
	}

	for _, vuln := range vs {
		if groupName == scanner.Acknowledged {
			md += fmt.Sprintf(
				"| %v | %v | %v | %v | %v | %v | %v | %v |\n",
				fmt.Sprintf("https://osv.dev/%s", vuln.Id),
				vuln.Severity,
				vuln.PackageEcosystem,
				vuln.PackageName,
				vuln.PackageVersion,
				markdownBoolean(vuln.FixAvailable),
				vuln.AckReason,
				vuln.Source,
			)
		} else {
			md += fmt.Sprintf(
				"| %v | %v | %v | %v | %v | %v | %v |\n",
				fmt.Sprintf("https://osv.dev/%s", vuln.Id),
				vuln.Severity,
				vuln.PackageEcosystem,
				vuln.PackageName,
				vuln.PackageVersion,
				markdownBoolean(vuln.FixAvailable),
				vuln.Source,
			)
		}
	}

	return
}

// markdownBoolean returns a markdown emoji for a boolean value
func markdownBoolean(b bool) string {
	if b {
		return "✅"
	}
	return "❌"
}

// getVulnReportHeader returns the header for the vulnerability report
func getVulnReportHeader() string {
	currentTime := now().Local()

	return fmt.Sprintf(`
ℹ️ This issue lists all the vulnerabilities found in the project by [Sheriff](https://github.com/elementsinteractive/sheriff) on %s.

Please review the vulnerabilities and take the necessary actions to fix or acknowledge them, see the [sheriff documentation](https://github.com/elementsinteractive/sheriff) for more information.`,
		currentTime.Format("2006-01-02"),
	)
}
