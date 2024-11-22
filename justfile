set dotenv-load := true

[no-exit-message]
run *ARGS:
    GITLAB_TOKEN=$GITLAB_TOKEN go run . {{ARGS}}

alias t := test
test *ARGS="./...":
    go test {{ARGS}}

lint:
    golangci-lint run ./... 
