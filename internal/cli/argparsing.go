package cli

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"

	"github.com/urfave/cli/v2"
)

const (
	// TODO: Figure out how to use custom types with a generic URL validator/parser
	Gitlab string = "gitlab"
	Issue  string = "issue"
	Slack  string = "slack"
)

var sourceCodePlatforms = []string{Gitlab}
var reportToPlatforms = []string{Slack, Issue}

var allPlatforms = append(sourceCodePlatforms, reportToPlatforms...)

var platformUrlRegex = map[string]string{
	Gitlab: gitlabPathRegex,
	Slack:  "^[a-z0-9-]{1}[a-z0-9-]{0,20}$",
	Issue:  "^$",
}

// validateURLs validates the URLs passed as arguments.
// It ensures that the URL is in the format "platform:path" and that the path matches the regex for the platform.
func validateURLs(validPrefixes []string) func(_ *cli.Context, urls []string) (err error) {
	return func(_ *cli.Context, urls []string) (err error) {
		for _, urlElem := range urls {
			parsed, err := url.Parse(urlElem)
			if err != nil {
				return errors.Join(errors.New("failed to parse URL"), err)
			}

			if !slices.Contains(validPrefixes, parsed.Scheme) {
				return fmt.Errorf("Unsupported repository service: %v", parsed.Scheme)
			}

			regex, ok := platformUrlRegex[parsed.Scheme]
			if !ok {
				return fmt.Errorf("No regex for platform: %v", parsed.Scheme)
			}

			// Check the URL
			rgx, err := regexp.Compile(regex)
			if err != nil {
				return err
			}

			matched := rgx.Match([]byte(parsed.Path))

			if !matched {
				return fmt.Errorf("invalid group path for platform: %v for %v", parsed.Path, parsed.Scheme)
			}

		}
		return
	}
}

// parseURLs parses the URLs passed as arguments returning a struct that
// separates the platform from the url part.
func parseURLs(urls []string) ([]*url.URL, error) {
	var parsedUrls []*url.URL

	for _, urlElem := range urls {
		parsed, err := url.Parse(urlElem)
		if err != nil {
			return nil, fmt.Errorf("failed to parse URL: %v", urlElem)
		}

		if !slices.Contains(allPlatforms, parsed.Scheme) {
			return nil, fmt.Errorf("Unsupported url Scheme (platform): %v", parsed.Scheme)
		}

		parsedUrls = append(parsedUrls, parsed)

	}

	return parsedUrls, nil
}

func getPlatformValueFromUrl(urlElems []*url.URL, platform string) []string {
	values := make([]string, 0)
	for _, elem := range urlElems {
		if elem.Scheme == platform {
			values = append(values, elem.Host+elem.Path)
		}
	}
	return values
}
