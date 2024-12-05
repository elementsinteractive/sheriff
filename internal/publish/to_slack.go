package publish

import (
	"errors"
	"fmt"
	"sheriff/internal/scanner"
	"sheriff/internal/slack"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
	goslack "github.com/slack-go/slack"
)

// PublishAsGeneralSlackMessage publishes a report of the vulnerabilities scanned to a slack channel
func PublishAsGeneralSlackMessage(channelName string, reports []scanner.Report, paths []string, s slack.IService) (err error) {
	vulnerableReportsBySeverityKind := groupVulnReportsByMaxSeverityKind(reports)

	summary := formatSummary(vulnerableReportsBySeverityKind, len(reports), paths)

	ts, err := s.PostMessage(channelName, summary...)
	if err != nil {
		return errors.Join(errors.New("failed to post slack summary"), err)
	}

	msgOptions := formatReportMessage(vulnerableReportsBySeverityKind)
	for _, option := range msgOptions {
		_, err = s.PostMessage(
			channelName,
			option,
			goslack.MsgOptionTS(ts), // Replies to the summary message in thread
		)
		if err != nil {
			return errors.Join(errors.New("failed to message in slack summary thread"), err)
		}
	}

	return
}

func PublishAsSpecificChannelSlackMessage(reports []scanner.Report, s slack.IService) (warn error) {
	configuredReports := pie.Filter(reports, func(r scanner.Report) bool { return r.ProjectConfig.ReportToSlackChannel != "" })

	var wg sync.WaitGroup
	for _, report := range configuredReports {
		wg.Add(1)

		go func() {
			defer wg.Done()
			message := formatSpecificChannelSlackMessage(report)

			_, err := s.PostMessage(report.ProjectConfig.ReportToSlackChannel, message...)
			if err != nil {
				log.Error().Err(err).Str("channel", report.ProjectConfig.ReportToSlackChannel).Msg("Failed to post slack report")
				err = fmt.Errorf("failed to post slack report to channel %v", report.ProjectConfig.ReportToSlackChannel)
				warn = errors.Join(err, warn)
			}
		}()
	}

	wg.Wait()

	return
}

func formatSpecificChannelSlackMessage(report scanner.Report) []goslack.MsgOption {
	// Count of vulnerabilities by severity
	nCritical := len(pie.Filter(report.Vulnerabilities, func(v scanner.Vulnerability) bool { return v.SeverityScoreKind == scanner.Critical }))
	nHigh := len(pie.Filter(report.Vulnerabilities, func(v scanner.Vulnerability) bool { return v.SeverityScoreKind == scanner.High }))
	nModerate := len(pie.Filter(report.Vulnerabilities, func(v scanner.Vulnerability) bool { return v.SeverityScoreKind == scanner.Moderate }))
	nLow := len(pie.Filter(report.Vulnerabilities, func(v scanner.Vulnerability) bool { return v.SeverityScoreKind == scanner.Low }))
	nUnknown := len(pie.Filter(report.Vulnerabilities, func(v scanner.Vulnerability) bool { return v.SeverityScoreKind == scanner.Unknown }))
	nAck := len(pie.Filter(report.Vulnerabilities, func(v scanner.Vulnerability) bool { return v.SeverityScoreKind == scanner.Acknowledged }))

	// Texts
	title := fmt.Sprintf("Sheriff Report %v", time.Now().Format("2006-01-02"))
	subtitle := fmt.Sprintf("Project: <%s|*%s*>", report.Project.WebURL, report.Project.PathWithNamespace)
	var subtitleFullReport string
	if report.IssueUrl != "" {
		subtitleFullReport = fmt.Sprintf("Full report: <%s|*Full report*>", report.IssueUrl)
	} else {
		subtitleFullReport = "\t_full report unavailable_\t\t"
	}
	countsTitle := fmt.Sprintf("*Vulnerability Counts* (total %v)", len(report.Vulnerabilities))
	criticalCount := fmt.Sprintf("Critical: *%v*", nCritical)
	highCount := fmt.Sprintf("High: *%v*", nHigh)
	moderateCount := fmt.Sprintf("Moderate: *%v*", nModerate)
	lowCount := fmt.Sprintf("Low: *%v*", nLow)
	unknownCount := fmt.Sprintf("Unknown: *%v*", nUnknown)
	ackCount := fmt.Sprintf("Acknowledged: *%v*", nAck)

	// Slack objects
	titleBlock := goslack.NewHeaderBlock(goslack.NewTextBlockObject("plain_text", title, true, false))
	subtitleBlock := goslack.NewContextBlock("subtitle", goslack.NewTextBlockObject("mrkdwn", subtitle, false, false))
	subtitleCountBlock := goslack.NewContextBlock("subtitleFullReport", goslack.NewTextBlockObject("mrkdwn", subtitleFullReport, false, false))
	countsTitleBlock := goslack.NewSectionBlock(goslack.NewTextBlockObject("mrkdwn", countsTitle, false, false), nil, nil)
	countsBlocks := []*goslack.TextBlockObject{
		goslack.NewTextBlockObject("mrkdwn", criticalCount, false, false),
		goslack.NewTextBlockObject("mrkdwn", highCount, false, false),
		goslack.NewTextBlockObject("mrkdwn", moderateCount, false, false),
		goslack.NewTextBlockObject("mrkdwn", lowCount, false, false),
		goslack.NewTextBlockObject("mrkdwn", unknownCount, false, false),
		goslack.NewTextBlockObject("mrkdwn", ackCount, false, false),
	}
	countsBlock := goslack.NewSectionBlock(nil, countsBlocks, nil)

	blocks := []goslack.Block{
		titleBlock,
		subtitleBlock,
		subtitleCountBlock,
		countsTitleBlock,
		countsBlock,
	}

	return []goslack.MsgOption{goslack.MsgOptionBlocks(blocks...)}
}

func formatSubtitleList(entity string, list []string) *goslack.ContextBlock {
	var text string
	if len(list) == 0 {
		text = fmt.Sprintf("no %v scanned", entity)
	} else if len(list) == 1 {
		text = fmt.Sprintf("%v scanned: %v", entity, list[0])
	} else {
		text = fmt.Sprintf("%v scanned:\n\t- %v", entity, strings.Join(list, "\n\t- "))
	}

	return goslack.NewContextBlock(fmt.Sprintf("%v-subtitle", entity), goslack.NewTextBlockObject("mrkdwn", text, false, false))
}

// formatSummary creates a message block with a summary of the reports
func formatSummary(reportsBySeverityKind map[scanner.SeverityScoreKind][]scanner.Report, totalReports int, paths []string) []goslack.MsgOption {
	title := goslack.NewHeaderBlock(
		goslack.NewTextBlockObject(
			"plain_text",
			fmt.Sprintf("Security Scan Report %v", time.Now().Format("2006-01-02")),
			true, false,
		),
	)
	subtitleGroups := formatSubtitleList("urls", paths)
	subtitleCount := goslack.NewContextBlock("subtitleCount", goslack.NewTextBlockObject("mrkdwn", fmt.Sprintf("Total projects scanned: %v", totalReports), false, false))

	counts := pie.Map(severityScoreOrder, func(kind scanner.SeverityScoreKind) *goslack.TextBlockObject {
		if group, ok := reportsBySeverityKind[kind]; ok {
			return goslack.NewTextBlockObject("mrkdwn", fmt.Sprintf("%v: *%v*", kind, len(group)), false, false)
		}
		return goslack.NewTextBlockObject("mrkdwn", fmt.Sprintf("%v: *%v*", kind, 0), false, false)
	})

	countsTitle := goslack.NewSectionBlock(goslack.NewTextBlockObject("mrkdwn", "*Vulnerability Counts*", false, false), nil, nil)
	countsBlock := goslack.NewSectionBlock(
		nil,
		counts,
		nil,
	)

	blocks := []goslack.Block{
		title,
		subtitleGroups,
		subtitleCount,
		countsTitle,
		countsBlock,
	}

	options := []goslack.MsgOption{goslack.MsgOptionBlocks(blocks...)}
	return options
}

// formatReportMessage formats the reports as a slack message, splitting the message into chunks if necessary
func formatReportMessage(reportsBySeverityKind map[scanner.SeverityScoreKind][]scanner.Report) (msgOptions []goslack.MsgOption) {
	text := strings.Builder{}
	for _, kind := range severityScoreOrder {
		if group, ok := reportsBySeverityKind[kind]; ok {
			if len(group) == 0 {
				continue
			}

			text.WriteString(fmt.Sprintf("Projects with vulnerabilities of *%v* severity\n", kind))
			for _, r := range group {
				projectName := fmt.Sprintf("<%s|*%s*>\n", r.Project.WebURL, r.Project.Name)
				var reportUrl string
				if r.IssueUrl != "" {
					reportUrl = fmt.Sprintf("\t<%s|Full report>\t\t", r.IssueUrl)
				} else {
					reportUrl = "\t_full report unavailable_\t\t"
				}
				vulnerabilityCount := fmt.Sprintf("\tVulnerability count: *%v*", len(r.Vulnerabilities))

				text.WriteString(projectName)
				text.WriteString(reportUrl)
				text.WriteString(vulnerabilityCount)
				text.WriteString("\n")
			}
			text.WriteString("\n")
		}
	}

	textString := text.String()
	// Slack has a 3001 character limit for messages
	splitText := splitMessage(textString, 3000)

	for _, chunk := range splitText {
		msgOptions = append(msgOptions, goslack.MsgOptionBlocks(goslack.NewSectionBlock(goslack.NewTextBlockObject("mrkdwn", chunk, false, false), nil, nil)))
	}

	return
}

// splitMessage splits a string into chunks of at most maxLen characters.
// Each chunk is determined by the closest newline character
func splitMessage(s string, maxLen int) []string {
	chunks := make([]string, 0, (len(s)/maxLen)+1)
	for len(s) > maxLen {
		idx := strings.LastIndex(s[:maxLen], "\n")
		if idx == -1 {
			// No newline found, split at maxLen
			idx = maxLen
		} else {
			// Newline found, include it in the current chunk
			idx = idx + 1
		}
		chunks = append(chunks, s[:idx])
		s = s[idx:]
	}
	chunks = append(chunks, s)
	return chunks
}

// getSeverityScoreOrder returns a slice of SeverityScoreKind sorted by their score in descending order
func getSeverityScoreOrder(thresholds map[scanner.SeverityScoreKind]float64) []scanner.SeverityScoreKind {
	kinds := make([]scanner.SeverityScoreKind, 0, len(thresholds))
	for kind := range thresholds {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool {
		return thresholds[kinds[i]] > thresholds[kinds[j]]
	})

	return kinds
}
