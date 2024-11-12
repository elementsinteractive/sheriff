package slack

import (
	"errors"
	"fmt"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
)

type IService interface {
	PostMessage(channelName string, options ...slack.MsgOption) (ts string, err error)
}

type service struct {
	client                  iclient
	isPublicChannelsEnabled bool
}

func New(token string, isPublicChannelsEnabled bool, debug bool) (IService, error) {
	slackClient := slack.New(token, slack.OptionDebug(debug))
	if slackClient == nil {
		return nil, errors.New("failed to create slack client")
	}

	s := service{&client{client: slackClient}, isPublicChannelsEnabled}

	return &s, nil
}

func (s *service) PostMessage(channelName string, options ...slack.MsgOption) (ts string, err error) {
	channel, err := s.findSlackChannel(channelName)
	if err != nil {
		return
	}

	_, ts, err = s.client.PostMessage(channel.ID, options...)
	if err != nil {
		return ts, errors.Join(errors.New("failed to post slack message"), err)
	}

	log.Info().Str("channel", channelName).Msg("Posted slack message")

	return
}

func (s *service) findSlackChannel(channelName string) (channel *slack.Channel, err error) {
	var nextCursor string
	var channels []slack.Channel
	var channelTypes = []string{"private_channel"}
	if s.isPublicChannelsEnabled {
		channelTypes = append(channelTypes, "public_channel")
	}

	for {
		if channels, nextCursor, err = s.client.GetConversations(&slack.GetConversationsParameters{
			ExcludeArchived: true,
			Cursor:          nextCursor,
			Types:           channelTypes,
			Limit:           1000,
		}); err != nil {
			return nil, errors.Join(errors.New("failed to get slack channel list"), err)
		}

		idx := pie.FindFirstUsing(channels, func(c slack.Channel) bool { return c.Name == channelName })
		if idx > -1 {
			log.Info().Str("channel", channelName).Msg("Found slack channel")
			channel = &channels[idx]
			return
		} else if nextCursor == "" {
			return nil, fmt.Errorf("channel %v not found", channelName)
		}

		log.Debug().Str("channel", channelName).Str("nextPage", nextCursor).Msg("Channel not found in current page, fetching next page")
	}
}
