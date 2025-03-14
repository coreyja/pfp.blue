#!/usr/bin/env bash

set -e

# Get the repository root directory
REPO_ROOT=$(git rev-parse --show-toplevel)
pushd "$REPO_ROOT" > /dev/null

# Print header function
print_header() {
  echo "===================================================================="
  echo "                         $1                                          "
  echo "===================================================================="
}

# Check if the PostgreSQL server is running
check_postgres() {
  if pg_isready -q; then
    echo "PostgreSQL server is running."
  else
    echo "ERROR: PostgreSQL server is not running."
    echo "Please start your PostgreSQL server before running this script."
    exit 1
  fi
}

# Run a command and check its return status
run_check() {
  print_header "$1"
  
  if "$@"; then
    echo "✅ $1 PASSED"
    echo ""
  else
    echo "❌ $1 FAILED"
    exit 1
  fi
}

# Verify postgres is running
check_postgres

# Prepare the database
print_header "PREPARING DATABASE"
./scripts/prepare_test_db.sh
echo "✅ DATABASE PREPARATION PASSED"
echo ""

# Check SQLX prepare
run_check "SQLX PREPARE CHECK" cargo sqlx prepare --workspace --check

# Check formatting
run_check "CARGO FORMAT" cargo fmt --all --check

# Run clippy
run_check "CARGO CLIPPY" cargo clippy --all-targets --workspace

# Run tests
run_check "CARGO TEST" cargo test --all-targets

# Run cargo-deny if installed
if command -v cargo-deny &> /dev/null; then
  run_check "CARGO DENY" cargo-deny check bans
else
  echo "⚠️  cargo-deny is not installed. Skipping dependency check."
  echo "To install cargo-deny, run:"
  echo "  cargo install cargo-deny"
  echo ""
fi

# Check if end2end tests would pass if we have the directory
if [ -d "$REPO_ROOT/end2end" ] && command -v pnpm &> /dev/null; then
  print_header "CHECKING END2END TESTS"
  pushd "$REPO_ROOT/end2end" > /dev/null
  
  if pnpm install --frozen-lockfile; then
    echo "✅ PNPM INSTALL PASSED"
    
    # We don't actually run the tests locally as they require a running server
    # Just check that the dependencies can be installed
    echo "ℹ️ Skipping actual Playwright tests (requires running server)"
    echo "✅ END2END CHECK PASSED"
  else
    echo "❌ PNPM INSTALL FAILED"
    popd > /dev/null
    exit 1
  fi
  
  popd > /dev/null
  echo ""
else
  echo "⚠️ Skipping end2end tests (directory not found or pnpm not installed)."
  echo ""
fi

print_header "LOCAL CI COMPLETED SUCCESSFULLY"
echo "All checks have passed! Your code is ready to be committed/pushed."
echo ""

popd > /dev/null