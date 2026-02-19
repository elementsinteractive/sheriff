package slack

import (
	"errors"
	"fmt"
	"time"

	"github.com/elliotchance/pie/v2"
	"github.com/rs/zerolog/log"
	"github.com/slack-go/slack"
)

type IService interface {
	PostMessage(channelName string, options ...slack.MsgOption) (ts string, err error)
}

type service struct {
	client         iclient
	maxAttempts    int
	initialBackoff time.Duration
}

type conversationsResult struct {
	Channels   []slack.Channel
	NextCursor string
}

// New creates a new Slack service
func New(token string, debug bool) (IService, error) {
	slackClient := slack.New(token, slack.OptionDebug(debug))
	if slackClient == nil {
		return nil, errors.New("failed to create slack client")
	}

	s := service{
		client:         &client{client: slackClient},
		maxAttempts:    5,
		initialBackoff: 2 * time.Second,
	}

	return &s, nil
}

// PostMessage posts a message to the given slack channel
func (s *service) PostMessage(channelName string, options ...slack.MsgOption) (ts string, err error) {
	channel, err := runWithRetries(func() (*slack.Channel, error) { return s.findSlackChannel(channelName) }, s.maxAttempts, s.initialBackoff)
	if err != nil {
		return
	}

	ts, err = runWithRetries(func() (string, error) {
		_, msgTs, err := s.client.PostMessage(channel.ID, options...)
		return msgTs, err
	}, s.maxAttempts, s.initialBackoff)
	if err != nil {
		return ts, errors.Join(errors.New("failed to post slack message"), err)
	}

	log.Info().Str("channel", channelName).Msg("Posted slack message")

	return
}

// findSlackChannel finds the slack channel by name.
// If the channel is not found, it returns an error.
func (s *service) findSlackChannel(channelName string) (channel *slack.Channel, err error) {
	var nextCursor string
	var channels []slack.Channel
	var channelTypes = []string{"private_channel", "public_channel"}

	for {
		result, opErr := runWithRetries(func() (conversationsResult, error) {
			convChannels, convCursor, convErr := s.client.GetConversations(&slack.GetConversationsParameters{
				ExcludeArchived: true,
				Cursor:          nextCursor,
				Types:           channelTypes,
				Limit:           1000,
			})
			if convErr != nil {
				return conversationsResult{}, convErr
			}
			return conversationsResult{Channels: convChannels, NextCursor: convCursor}, nil
		}, s.maxAttempts, s.initialBackoff)
		if opErr != nil {
			return nil, errors.Join(errors.New("failed to get slack channel list"), opErr)
		}

		channels = result.Channels
		nextCursor = result.NextCursor

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

func runWithRetries[T any](operation func() (T, error), maxAttempts int, backoff time.Duration) (result T, err error) {
	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, err = operation()
		if err == nil {
			return result, nil
		}

		if attempt == maxAttempts {
			break
		}

		var sleepDuration time.Duration
		var rateLimitErr *slack.RateLimitedError

		if errors.As(err, &rateLimitErr) {
			// Override the standard backoff with Slack's requested wait time
			if rateLimitErr.RetryAfter > 0 {
				sleepDuration = rateLimitErr.RetryAfter
			} else {
				// Use exponential backoff: backoff * 2^(attempt-1)
				sleepDuration = backoff * time.Duration(1<<(attempt-1))
			}

			log.Warn().
				Err(err).
				Int("attempt", attempt).
				Dur("retry_after", sleepDuration).
				Msg("Hit Slack rate limit, backing off dynamically")
		} else {
			sleepDuration = backoff * time.Duration(1<<(attempt-1))
			log.Warn().Err(err).Int("attempt", attempt).Dur("backoff", sleepDuration).Msg("Operation failed, retrying with exponential backoff")
		}

		time.Sleep(sleepDuration)
	}

	return result, fmt.Errorf("operation failed after %d attempts: %w", maxAttempts, err)
}
