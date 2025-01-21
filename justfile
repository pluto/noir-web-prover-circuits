default:
    @just --list

[private]
warn := "\\033[33m"
error := "\\033[31m"
info := "\\033[34m"
success := "\\033[32m"
reset := "\\033[0m"
bold := "\\033[1m"

# Print formatted headers without shell scripts
[private]
header msg:
    @printf "{{info}}{{bold}}==> {{msg}}{{reset}}\n"

# Get native architecture
[private]
native_arch := if `uname -m` == "arm64" { "aarch64" } else { `uname -m` }

# Install Noirup and Nargo
install-noir:
    curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash noirup

# Install Noirup and Nargo
install-constraint-counter:
    cargo install --path constraint_counter

# Install cargo tools
install-tools:
    @just header "Installing tools"
    # taplo
    if ! command -v taplo > /dev/null; then \
        printf "{{info}}Installing taplo...{{reset}}\n" && \
        cargo install taplo-cli; \
    else \
        printf "{{success}}✓ taplo already installed{{reset}}\n"; \
    fi

# Setup complete development environment
setup: install-tools install-noir install-constraint-counter
    @printf "{{success}}{{bold}}Development environment setup complete!{{reset}}\n"

# Build entire Nargo workspace with local target
build:
    @just header "Building workspace"
    nargo build --workspace --expression-width 0

# Run tests for Nargo workspace
test:
    @just header "Running native architecture tests"
    nargo test --workspace

# Run format for the workspace
fmt:
    @just header "Formatting code"
    nargo fmt --workspace
    taplo fmt

# Run all CI checks
ci:
    @printf "{{bold}}Starting CI checks{{reset}}\n\n"
    @ERROR=0; \
    just run-single-check "Noir formatting" "nargo fmt --workspace --check" || ERROR=1; \
    just run-single-check "TOML formatting" "taplo fmt --check" || ERROR=1; \
    just run-single-check "Tests" "nargo test --workspace" || ERROR=1; \
    printf "\n{{bold}}CI Summary:{{reset}}\n"; \
    if [ $ERROR -eq 0 ]; then \
        printf "{{success}}{{bold}}All checks passed successfully!{{reset}}\n"; \
    else \
        printf "{{error}}{{bold}}Some checks failed. See output above for details.{{reset}}\n"; \
        exit 1; \
    fi

# Run a single check and return status (0 = pass, 1 = fail)
[private]
run-single-check name command:
    #!/usr/bin/env sh
    printf "{{info}}{{bold}}Running{{reset}} {{info}}%s{{reset}}...\n" "{{name}}"
    if {{command}} > /tmp/check-output 2>&1; then
        printf "  {{success}}{{bold}}PASSED{{reset}}\n"
        exit 0
    else
        printf "  {{error}}{{bold}}FAILED{{reset}}\n"
        printf "{{error}}----------------------------------------\n"
        while IFS= read -r line; do
            printf "{{error}}%s{{reset}}\n" "$line"
        done < /tmp/check-output
        printf "{{error}}----------------------------------------{{reset}}\n"
        exit 1
    fi