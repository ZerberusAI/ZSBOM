# Scalibr Cross-Platform Build Makefile
# Builds shared libraries for multiple platforms and architectures

.PHONY: all clean linux macos windows linux-amd64 linux-arm64 macos-amd64 macos-arm64 windows-amd64 deps

# Default target builds for current platform
all: detect-platform

# Download Go dependencies
deps:
	@echo "Downloading Go dependencies..."
	@go mod download
	@echo "✅ Dependencies downloaded successfully"

# Detect current platform and build appropriate binary
detect-platform:
	@echo "Detecting platform and building Scalibr shared library..."
	@if [ "$$(uname)" = "Linux" ]; then \
		if [ "$$(uname -m)" = "x86_64" ]; then \
			$(MAKE) linux-amd64; \
		elif [ "$$(uname -m)" = "aarch64" ]; then \
			$(MAKE) linux-arm64; \
		else \
			echo "Unsupported Linux architecture: $$(uname -m)"; \
			exit 1; \
		fi \
	elif [ "$$(uname)" = "Darwin" ]; then \
		if [ "$$(uname -m)" = "x86_64" ]; then \
			$(MAKE) macos-amd64; \
		elif [ "$$(uname -m)" = "arm64" ]; then \
			$(MAKE) macos-arm64; \
		else \
			echo "Unsupported macOS architecture: $$(uname -m)"; \
			exit 1; \
		fi \
	else \
		echo "Unsupported platform: $$(uname)"; \
		echo "Please build manually using: go build -buildmode=c-shared -o scalibr.so scalibr_wrapper.go"; \
		exit 1; \
	fi

# Linux builds
linux: linux-amd64 linux-arm64

linux-amd64: deps
	@echo "Building for Linux AMD64..."
	GOOS=linux GOARCH=amd64 go build -buildmode=c-shared -o scalibr-linux-amd64.so scalibr_wrapper.go
	@if [ "$$(uname)" = "Linux" ] && [ "$$(uname -m)" = "x86_64" ]; then \
		cp scalibr-linux-amd64.so scalibr.so; \
	fi

linux-arm64: deps
	@echo "Building for Linux ARM64..."
	GOOS=linux GOARCH=arm64 go build -buildmode=c-shared -o scalibr-linux-arm64.so scalibr_wrapper.go

# macOS builds
macos: macos-amd64 macos-arm64

macos-amd64: deps
	@echo "Building for macOS AMD64..."
	GOOS=darwin GOARCH=amd64 go build -buildmode=c-shared -o scalibr-darwin-amd64.dylib scalibr_wrapper.go
	@if [ "$$(uname)" = "Darwin" ] && [ "$$(uname -m)" = "x86_64" ]; then \
		cp scalibr-darwin-amd64.dylib scalibr.dylib; \
	fi

macos-arm64: deps
	@echo "Building for macOS ARM64..."
	GOOS=darwin GOARCH=arm64 go build -buildmode=c-shared -o scalibr-darwin-arm64.dylib scalibr_wrapper.go
	@if [ "$$(uname)" = "Darwin" ] && [ "$$(uname -m)" = "arm64" ]; then \
		cp scalibr-darwin-arm64.dylib scalibr.dylib; \
	fi

# Windows builds (requires CGO_ENABLED=1 and mingw-w64)
windows: windows-amd64

windows-amd64: deps
	@echo "Building for Windows AMD64..."
	@echo "Note: Windows builds require CGO_ENABLED=1 and mingw-w64 cross-compiler"
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc go build -buildmode=c-shared -o scalibr-windows-amd64.dll scalibr_wrapper.go

# Build all platforms (CI/CD use)
all-platforms: linux macos
	@echo "Built binaries for all supported platforms"
	@ls -la scalibr-*

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f scalibr.so scalibr.dylib scalibr.dll
	rm -f scalibr-*.so scalibr-*.dylib scalibr-*.dll scalibr.h
	@echo "Cleaned."

# Show build information
info:
	@echo "Scalibr Build Information:"
	@echo "=========================="
	@echo "Current OS: $$(uname)"
	@echo "Current Arch: $$(uname -m)"
	@echo "Go Version: $$(go version || echo 'Go not found')"
	@echo ""
	@echo "Supported targets:"
	@echo "  linux-amd64    - Linux x86_64 (.so)"
	@echo "  linux-arm64    - Linux ARM64 (.so)"
	@echo "  macos-amd64    - macOS Intel (.dylib)"
	@echo "  macos-arm64    - macOS Apple Silicon (.dylib)"
	@echo "  windows-amd64  - Windows x86_64 (.dll)"

# Development target - quick build for current platform
dev: deps
	@echo "Quick development build for current platform..."
	go build -buildmode=c-shared -o scalibr.so scalibr_wrapper.go
	@echo "Built scalibr.so for development"