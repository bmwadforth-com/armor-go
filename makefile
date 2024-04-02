# Targets
all: build test

build:
	go build -o galaxy ./src/**

test:
	go test -v ./...

clean:
	rm -f galaxy

# Optional targets (add as needed)
lint:
	golangci-lint run

coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

.PHONY: all build test clean lint coverage
