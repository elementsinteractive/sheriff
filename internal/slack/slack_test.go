package slack

import (
	"testing"

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

	svc := service{&mockClient}

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

	svc := service{&mockClient}

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
