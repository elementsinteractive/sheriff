package slack

import (
	"errors"
	"testing"
	"time"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestNewService(t *testing.T) {
	s, err := New("token", false)

	assert.Nil(t, err)
	assert.NotNil(t, s)
}

func TestPostMessage(t *testing.T) {
	channelID := "1234"
	channelName := "random channel"
	message := slack.MsgOptionText("Hello World", false)

	mockClient := mockClient{}
	mockClient.On("GetConversations", mock.Anything).Return(
		[]slack.Channel{
			{
				GroupConversation: slack.GroupConversation{
					Conversation: slack.Conversation{ID: channelID},
					Name:         channelName,
				},
			},
		},
		"",
		nil,
	)
	mockClient.On("PostMessage", channelID, mock.Anything).Return("", "", nil)

	svc := service{
		client:         &mockClient,
		maxAttempts:    3,
		initialBackoff: 2 * time.Second,
	}

	_, err := svc.PostMessage(channelName, message)

	assert.Nil(t, err)
	mockClient.AssertExpectations(t)
}

func TestFindSlackChannel(t *testing.T) {
	channelID := "1234"
	channelName := "random channel"

	mockClient := mockClient{}
	mockClient.On("GetConversations", &slack.GetConversationsParameters{
		ExcludeArchived: true,
		Cursor:          "",
		Types:           []string{"private_channel", "public_channel"},
		Limit:           1000,
	}).Return(
		[]slack.Channel{
			{
				GroupConversation: slack.GroupConversation{
					Conversation: slack.Conversation{ID: channelID},
					Name:         channelName,
				},
			},
		},
		"",
		nil,
	)

	svc := service{
		client:         &mockClient,
		maxAttempts:    3,
		initialBackoff: 2 * time.Second,
	}

	channel, err := svc.findSlackChannel(channelName)

	assert.Nil(t, err)
	assert.NotNil(t, channel)
	assert.Equal(t, channelID, channel.ID)

}

type mockClient struct {
	mock.Mock
}

func (c *mockClient) PostMessage(channelID string, options ...slack.MsgOption) (string, string, error) {
	args := c.Called(channelID, options)
	return args.String(0), args.String(1), args.Error(2)
}

func (c *mockClient) GetConversations(params *slack.GetConversationsParameters) (channels []slack.Channel, nextCursor string, err error) {
	args := c.Called(params)
	return args.Get(0).([]slack.Channel), args.String(1), args.Error(2)
}

// TestPostMessageWithRateLimitRetry verifies retry happens on rate limit errors
func TestPostMessageWithRateLimitRetry(t *testing.T) {
	channelID := "test-channel"

	mockClient := mockClient{}
	mockClient.On("GetConversations", mock.Anything).Return(
		[]slack.Channel{
			{
				GroupConversation: slack.GroupConversation{
					Conversation: slack.Conversation{ID: channelID},
					Name:         "test-channel",
				},
			},
		},
		"",
		nil,
	)
	// First call fails with rate limit
	mockClient.On("PostMessage", channelID, mock.Anything).Return("", "", errors.New("error: rate limit")).Once()
	// Second call succeeds
	mockClient.On("PostMessage", channelID, mock.Anything).Return("", "ts123", nil).Once()

	// Create service with minimal backoff for testing (1ms instead of 2s)
	svc := service{
		client:         &mockClient,
		maxAttempts:    3,
		initialBackoff: 1 * time.Microsecond,
	}

	start := time.Now()
	ts, err := svc.PostMessage(channelID, slack.MsgOptionText("test", false))

	assert.Nil(t, err)
	assert.Equal(t, "ts123", ts)
	mockClient.AssertExpectations(t)

	// Verify it waited (at least the backoff time, which is now 1ms)
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, 1*time.Microsecond, "should have waited for backoff")
}
func TestPostMessageWithDynamicRateLimitRetry(t *testing.T) {
	channelID := "test-channel"
	mockClient := mockClient{}

	// Setup mock channel resolution
	mockClient.On("GetConversations", mock.Anything).Return(
		[]slack.Channel{
			{
				GroupConversation: slack.GroupConversation{
					Conversation: slack.Conversation{ID: channelID},
					Name:         "test-channel",
				},
			},
		},
		"",
		nil,
	)

	expectedWait := 50 * time.Millisecond
	rateLimitErr := &slack.RateLimitedError{
		RetryAfter: expectedWait,
	}

	mockClient.On("PostMessage", channelID, mock.Anything).
		Return("", "", rateLimitErr).Once()

	mockClient.On("PostMessage", channelID, mock.Anything).
		Return("", "ts123", nil).Once()

	svc := service{
		client:         &mockClient,
		maxAttempts:    3,
		initialBackoff: 1 * time.Millisecond,
	}

	start := time.Now()
	ts, err := svc.PostMessage(channelID, slack.MsgOptionText("test", false))

	assert.Nil(t, err)
	assert.Equal(t, "ts123", ts)
	mockClient.AssertExpectations(t)

	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, expectedWait, "should have used Slack's dynamic RetryAfter backoff")
}

func TestChannelIsCached(t *testing.T) {
	channelID := "1234"
	channelName := "random channel"

	mockClient := mockClient{}
	mockClient.On("GetConversations", &slack.GetConversationsParameters{
		ExcludeArchived: true,
		Cursor:          "",
		Types:           []string{"private_channel", "public_channel"},
		Limit:           1000,
	}).Return(
		[]slack.Channel{
			{
				GroupConversation: slack.GroupConversation{
					Conversation: slack.Conversation{ID: channelID},
					Name:         channelName,
				},
			},
		},
		"",
		nil,
	).Once() // Expect only one call to GetConversations

	svc := service{
		client:         &mockClient,
		maxAttempts:    3,
		initialBackoff: 2 * time.Second,
	}

	channel, err := svc.findSlackChannel(channelName)
	assert.Nil(t, err)
	assert.NotNil(t, channel)
	assert.Equal(t, channelID, channel.ID)

	// Call again to verify it uses the cache
	cachedChannel, err := svc.findSlackChannel(channelName)
	assert.Nil(t, err)
	assert.NotNil(t, cachedChannel)
	assert.Equal(t, channelID, cachedChannel.ID)

	mockClient.AssertExpectations(t)
}
