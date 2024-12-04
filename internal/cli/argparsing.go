package cli

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/urfave/cli/v2"
)

// genericUrlElem is a struct to store a platform and a URL.
// The url can represent different things depending on the platform in question:
// For slack, it may represent a channel; for gitlab, it may represent a project, etc.
type genericUrlElem struct {
	Platform string
	Url      string
}

// validateURLs validates the URLs passed as arguments.
// It ensures that the URL is in the format "platform:path" and that the path matches the regex for the platform.
func validateURLs(validPrefixes []string) func(_ *cli.Context, urls []string) (err error) {
	return func(_ *cli.Context, urls []string) (err error) {
		for _, url := range urls {
			parts := strings.Split(url, "://")
			if len(parts) != 2 {
				return fmt.Errorf("invalid url: %v", url)
			}

			platform := parts[0]

			if !slices.Contains(validPrefixes, platform) {
				return fmt.Errorf("Unsupported repository service: %v", platform)
			}

			regex, ok := platformUrlRegex[platform]
			if !ok {
				return fmt.Errorf("No regex for platform: %v", platform)
			}

			// Check the URL
			rgx, err := regexp.Compile(regex)
			if err != nil {
				return err
			}

			path := parts[1]
			matched := rgx.Match([]byte(path))

			if !matched {
				return fmt.Errorf("invalid group path for platform: %v for %v", path, platform)
			}

		}
		return
	}
}

// parseURLs parses the URLs passed as arguments returning a struct that
// separates the platform from the url part.
func parseURLs(urls []string) ([]genericUrlElem, error) {
	var parsedUrls []genericUrlElem

	for _, url := range urls {
		parts := strings.Split(url, "://")
		if len(parts) != 2 {
			// This should never happen, as the URL should have been validated before
			return nil, fmt.Errorf("invalid url: %v", url)
		}
		parsedUrls = append(parsedUrls, genericUrlElem{
			Platform: parts[0],
			Url:      parts[1],
		})
	}

	return parsedUrls, nil
}

func getPlatformValueFromUrl(urlElems []genericUrlElem, platform string) []string {
	values := make([]string, 0)
	for _, elem := range urlElems {
		if elem.Platform == platform {
			values = append(values, elem.Url)
		}
	}
	return values
}
