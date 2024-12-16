package config

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetConfiguration(t *testing.T) {
	testCases := []struct {
		foldername string
		wantConfig ProjectConfig
	}{
		{"valid", ProjectConfig{ReportToSlackChannel: "the-devils-slack-channel"}},
		{"invalid", ProjectConfig{}},
		{"nonexistent", ProjectConfig{}},
		{"valid_with_ack", ProjectConfig{Acknowledged: []AcknowledgedVuln{{Code: "CSV111", Reason: "not relevant"}, {Code: "CSV222", Reason: ""}}}},
		{"valid_with_ack_alt", ProjectConfig{Acknowledged: []AcknowledgedVuln{{Code: "CSV111", Reason: "not relevant"}, {Code: "CSV222", Reason: ""}}}},
	}

	for _, tc := range testCases {
		t.Run(tc.foldername, func(t *testing.T) {
			got := GetProjectConfiguration("", fmt.Sprintf("testdata/project/%v", tc.foldername))

			assert.Equal(t, tc.wantConfig, got)
		})
	}
}
