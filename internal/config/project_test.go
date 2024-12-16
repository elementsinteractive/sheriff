package config

import (
	"sheriff/internal/scanner"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetConfiguration(t *testing.T) {
	testCases := []struct {
		filename   string
		wantFound  bool
		wantErr    bool
		wantConfig scanner.ProjectConfig
	}{
		{"testdata/valid.toml", true, false, scanner.ProjectConfig{ReportToSlackChannel: "the-devils-slack-channel"}},
		{"testdata/invalid.toml", true, true, scanner.ProjectConfig{}},
		{"testdata/nonexistent.toml", false, false, scanner.ProjectConfig{}},
		{"testdata/valid_with_ack.toml", true, false, scanner.ProjectConfig{Acknowledged: []scanner.AcknowledgedVuln{{Code: "CSV111", Reason: "not relevant"}, {Code: "CSV222", Reason: ""}}}},
		{"testdata/valid_with_ack_alt.toml", true, false, scanner.ProjectConfig{Acknowledged: []scanner.AcknowledgedVuln{{Code: "CSV111", Reason: "not relevant"}, {Code: "CSV222", Reason: ""}}}},
	}

	for _, tc := range testCases {
		t.Run(tc.filename, func(t *testing.T) {
			got, found, err := GetConfiguration(tc.filename)

			assert.Equal(t, tc.wantFound, found)
			assert.Equal(t, err != nil, tc.wantErr)
			assert.Equal(t, tc.wantConfig, got)
		})
	}
}
