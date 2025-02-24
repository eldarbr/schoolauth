DISABLED_LINTERS="depguard"

all:

example:
	go build -o bin/ example/main.go

test:
	go test -v -count=1 ./...

fmt:
	go fmt ./...

lint:
	go vet ./...
	golangci-lint run --enable-all --color=never --disable=$(DISABLED_LINTERS)

clean:
	rm -rf bin

generate:

.PHONY: all example test fmt lint clean generate
