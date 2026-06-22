
BINARY    := kitfind
VERSION   := 1.0.0
LDFLAGS   := -ldflags="-s -w -X main.version=$(VERSION)"
BUILD_DIR := ./dist

.PHONY: all build install test lint clean docker help

all: build


build:
	@echo "Building $(BINARY)..."
	@CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) ./cmd/kitfind/
	@echo "✓ Built ./$(BINARY)"


install: build
	@sudo cp $(BINARY) /usr/local/bin/$(BINARY)
	@echo "✓ Installed to /usr/local/bin/$(BINARY)"


cross:
	@./scripts/build.sh


test:
	@go test -short -v -race ./tests/unit/...


test-all:
	@go test -v ./tests/unit/...


coverage:
	@go test -short -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report: coverage.html"


lint:
	@golangci-lint run ./...


tidy:
	@go mod tidy
	@echo "✓ go.mod tidied"


clean:
	@rm -f $(BINARY) coverage.out coverage.html
	@rm -rf $(BUILD_DIR)
	@echo "✓ Cleaned"


docker-build:
	@docker build -f docker/Dockerfile -t kitfind:$(VERSION) -t kitfind:latest .
	@echo "✓ Docker image: kitfind:$(VERSION)"


docker-run:
	@docker run --rm -it kitfind:latest $(ARGS)


scan: build
	@./$(BINARY) scan $(TARGET)


help:
	@grep -E '^##' Makefile | sed 's/## /  /'

