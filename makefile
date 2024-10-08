# Targets
all: build test

build:
	go build ./src/...

test:
	go test -v ./test/...

clean:
	rm -f armor-go

# Optional targets (add as needed)
lint:
	golangci-lint run

coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

.PHONY: all build test clean lint coverage
