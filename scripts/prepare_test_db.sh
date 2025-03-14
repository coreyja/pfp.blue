#!/usr/bin/env bash

set -e

# Get the repository root directory
REPO_ROOT=$(git rev-parse --show-toplevel)
pushd "$REPO_ROOT" > /dev/null

# Create the database if it doesn't exist
cargo sqlx database create

# Run migrations to prepare the database schema
cargo sqlx migrate run

popd > /dev/null