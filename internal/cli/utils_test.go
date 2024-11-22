package cli

import (
	"flag"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/urfave/cli/v2"
)

func TestCombineBeforeFuncs(t *testing.T) {
	mockBeforeFuncs := new(mockBeforeFuncs)
	mockBeforeFuncs.On("Func1", mock.Anything).Return(nil)
	mockBeforeFuncs.On("Func2", mock.Anything).Return(nil)

	before_func := CombineBeforeFuncs(mockBeforeFuncs.Func1, mockBeforeFuncs.Func2)

	_ = before_func(nil)

	mockBeforeFuncs.AssertExpectations(t)
}

type mockBeforeFuncs struct {
	mock.Mock
}

func (m *mockBeforeFuncs) Func1(cCtx *cli.Context) error {
	args := m.Called(cCtx)
	return args.Error(0)
}

func (m *mockBeforeFuncs) Func2(cCtx *cli.Context) error {
	args := m.Called(cCtx)
	return args.Error(0)
}

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

// Tests for ConfigFileLoader when no file is found.
// There should be an equivalent test for when the file is found, but it's tough.
func TestConfigFileLoaderNoFile(t *testing.T) {
	flag := flag.NewFlagSet("config", flag.ContinueOnError)
	flag.String("config", "nonexistent", "")
	context := cli.NewContext(nil, flag, nil)

	beforeFunc := GetConfigFileLoader(nil, "config")
	err := beforeFunc(context)

	assert.Nil(t, err)
}

func TestLogArguments(t *testing.T) {
	flag := flag.NewFlagSet("flag", flag.ContinueOnError)
	flag.String("some-flag", "", "")
	_ = flag.Set("some-flag", "value")
	context := cli.NewContext(nil, flag, nil)

	_ = LogArguments(context)

	// How to assert that the log message was correct?
}
