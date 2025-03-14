#!/usr/bin/env bash
set -euo pipefail

# Script to run end-to-end tests for local development

# Function to clean up processes on exit
cleanup() {
  echo -e "\n🧹 Cleaning up processes..."
  
  # Kill any running Overmind processes
  if pgrep -f "overmind start -f" > /dev/null; then
    echo "🛑 Stopping Overmind processes..."
    pkill -f "overmind start -f" || true
  fi
  
  # Kill any lingering test server processes
  for proc in "pds" "plc-directory" "appview" "pfp-blue"; do
    if pgrep -f "cargo run --bin $proc" > /dev/null; then
      echo "🛑 Stopping $proc process..."
      pkill -f "cargo run --bin $proc" || true
    fi
  done

  # Remove any stale socket files
  if [ -f ./.overmind.sock ]; then
    echo "🗑️  Removing stale Overmind socket file..."
    rm -f ./.overmind.sock
  fi

  echo "✅ Cleanup complete"
}

# Set up trap to ensure cleanup on exit
trap cleanup EXIT INT TERM

# Run cleanup at the start to ensure we're starting fresh
cleanup

# Default options
TEST_MODE="headed"    # Run in headed mode by default
USE_FIXTURES=true     # Use fixture servers by default
BROWSER="chromium"    # Default browser
TEST_FILTER=""        # No filter by default
DEBUG=false           # Debug mode off by default

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --browser|-b)
      BROWSER="$2"
      shift 2
      ;;
    --headless)
      TEST_MODE="headless"
      shift
      ;;
    --no-fixtures)
      USE_FIXTURES=false
      shift
      ;;
    --real-services)
      USE_FIXTURES=false
      shift
      ;;
    --test|-t)
      TEST_FILTER="test=$2"
      shift 2
      ;;
    --debug|-d)
      DEBUG=true
      shift
      ;;
    --help|-h)
      echo "Usage: $0 [options]"
      echo ""
      echo "Options:"
      echo "  --browser, -b <browser>   Specify browser (chromium, firefox, webkit)"
      echo "  --headless                Run in headless mode"
      echo "  --no-fixtures             Don't use fixture servers (uses real services)"
      echo "  --real-services           Same as --no-fixtures"
      echo "  --test, -t <pattern>      Run tests matching pattern"
      echo "  --debug, -d               Run tests in debug mode"
      echo "  --help, -h                Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $key"
      exit 1
      ;;
  esac
done

# Validate browser option
if [[ ! "$BROWSER" =~ ^(chromium|firefox|webkit)$ ]]; then
  echo "Error: Browser must be one of: chromium, firefox, webkit"
  exit 1
fi

# Build the command based on options
COMMAND="pnpm "

if $USE_FIXTURES; then
  echo "🔄 Using fixture servers for testing"
  COMMAND+="test:fixtures:"
else
  echo "🌐 Using real services for testing"
  COMMAND+="test:"
fi

if [[ "$TEST_MODE" == "headed" ]]; then
  COMMAND+="headed"
else
  echo "🔍 Running in headless mode"
  COMMAND+=""
fi

# Add browser selection
COMMAND+=" --project=$BROWSER"

# Add debug option if specified
if $DEBUG; then
  echo "🐛 Running in debug mode"
  COMMAND+=" --debug"
fi

# Add test filter if specified
if [[ -n "$TEST_FILTER" ]]; then
  echo "🔍 Filtering tests: $TEST_FILTER"
  COMMAND+=" $TEST_FILTER"
fi

# Display and run the command
echo -e "\n📊 Running: $COMMAND\n"
eval "$COMMAND"

# Exit code will be that of the test command
exit_code=$?
echo -e "\n⏱️  Tests completed with exit code: $exit_code"

# The cleanup function will be called automatically due to the trap
exit $exit_code