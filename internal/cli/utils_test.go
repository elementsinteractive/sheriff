package cli

import (
	"flag"
	"strconv"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
)

func TestConfigureLogs(t *testing.T) {
	testCases := map[bool]zerolog.Level{
		true:  zerolog.DebugLevel,
		false: zerolog.WarnLevel,
	}

	for input, want := range testCases {
		flag := flag.NewFlagSet("verbose", flag.ContinueOnError)
		flag.Bool("verbose", input, "")
		context := cli.NewContext(nil, flag, nil)

		_ = ConfigureLogs(context)

		assert.Equal(t, zerolog.GlobalLevel(), want)
	}
}

func TestGetStringIfSettest(t *testing.T) {
	want := "hello"
	flagName := "testFlag"

	flag := flag.NewFlagSet("", flag.ContinueOnError)
	flag.String(flagName, "", "")
	_ = flag.Set(flagName, want)
	cCtx := cli.NewContext(nil, flag, nil)

	got := getStringIfSet(cCtx, flagName)

	assert.Equal(t, want, *got)
}

func TestGetStringIfSet(t *testing.T) {
	testCases := []struct {
		name string
		want string
		set  bool
	}{{
		name: "value",
		want: "hello",
		set:  true,
	}, {
		name: "nil",
		want: "",
		set:  false,
	}}

	flagName := "testFlag"
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flag := flag.NewFlagSet("", flag.ContinueOnError)
			flag.String(flagName, "", "")
			if tc.set {
				_ = flag.Set(flagName, tc.want)
			}
			cCtx := cli.NewContext(nil, flag, nil)

			got := getStringIfSet(cCtx, flagName)

			if tc.set {
				assert.NotNil(t, got)
				assert.Equal(t, tc.want, *got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func TestGetStringSliceIfSet(t *testing.T) {
	testCases := []struct {
		name string
		want []string
		set  bool
	}{{
		name: "value",
		want: []string{"hello", "world"},
		set:  true,
	}, {
		name: "nil",
		want: []string{},
		set:  false,
	}}

	flagName := "testFlag"
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flag := flag.NewFlagSet("", flag.ContinueOnError)
			flag.Var(&cli.StringSlice{}, flagName, "")
			if tc.set {
				_ = flag.Set(flagName, strings.Join(tc.want, ", "))
			}
			cCtx := cli.NewContext(nil, flag, nil)

			got := getStringSliceIfSet(cCtx, flagName)

			if tc.set {
				assert.NotNil(t, got)
				assert.Equal(t, tc.want, *got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}

func TestGetBoolIfSet(t *testing.T) {
	testCases := []struct {
		name string
		want bool
		set  bool
	}{{
		name: "value",
		want: true,
		set:  true,
	}, {
		name: "nil",
		want: false,
		set:  false,
	}}

	flagName := "testFlag"
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flag := flag.NewFlagSet("", flag.ContinueOnError)
			flag.Bool(flagName, false, "")
			if tc.set {
				_ = flag.Set(flagName, strconv.FormatBool(tc.want))
			}
			cCtx := cli.NewContext(nil, flag, nil)

			got := getBoolIfSet(cCtx, flagName)

			if tc.set {
				assert.NotNil(t, got)
				assert.Equal(t, tc.want, *got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}
