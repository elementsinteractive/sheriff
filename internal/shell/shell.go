package shell

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

const defaultTimeout = 5 * time.Second

// commandRunnerInterface is an interface that defines the Run method for running shell commands.
type commandRunnerInterface interface {
	Run(in CommandInput) (CommandOutput, error)
}

// CommandOutput is a struct that contains the output of a shell command
// and the exit code of the command. If the command was not executed at all,
// (for instance, due to a timeout), the exit code will be -1.
type CommandOutput struct {
	Output   []byte
	ExitCode int
}

// CommandInput is a struct that contains the input for a shell command.
type CommandInput struct {
	Name    string
	Args    []string
	Timeout time.Duration
}

// CommandRunner is a struct that implements the CommandRunnerInterface
// It is used to run shell commands, encapsulating the exec.Command function.
type shellCommandRunner struct{}

// Run runs a shell command with the given input and returns the output and error.
// If the given CommandInput timeout is 0, it will default to 5 seconds.
func (c *shellCommandRunner) Run(in CommandInput) (CommandOutput, error) {
	if in.Timeout == 0 {
		in.Timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), in.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, in.Name, in.Args...)
	out, err := cmd.Output()

	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			// Something went wrong, but the command did not exit at all with an exit code
			exitCode = -1
		}
	}

	return CommandOutput{
		Output:   out,
		ExitCode: exitCode,
	}, err
}

// ShellCommandRunner is a global variable that is used to run shell commands.
var ShellCommandRunner commandRunnerInterface = &shellCommandRunner{}
