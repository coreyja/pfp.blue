# Fixtures for pfp.blue

This crate provides mock servers for the external web services that the pfp.blue application interacts with. These fixtures allow for reliable end-to-end testing without dependencies on external APIs.

## Available Fixtures

### 1. PDS (Personal Data Server)

Mock server for Bluesky's Personal Data Server, handling requests for profiles, blobs, and authentication.

```bash
cargo run --bin pds -- --port 3001
```

### 2. AppView

Mock server for Bluesky's AppView service, handling actor resolution, profiles, and searches.

```bash
cargo run --bin appview -- --port 3003
```

### 3. PLC Directory

Mock server for the PLC Directory service that handles DID resolution.

```bash
cargo run --bin plc-directory -- --port 3002
```

## Command Line Options

All fixtures support the following command line options:

- `-p, --port <PORT>`: The port to listen on (default: random available port)
- `-H, --host <HOST>`: The host to bind to (default: 127.0.0.1)
- `-d, --data <DATA>`: Path to JSON file with custom fixture data
- `--force`: Run even if required environment variables are missing

## Environment Variables

The fixtures communicate with each other using environment variables:

- `PDS_URL`: URL of the PDS fixture (used by PLC Directory fixture)
- `AVATAR_CDN_URL`: URL of the Avatar CDN, which is served by the AppView fixture

## Using with End-to-End Tests

The recommended way to use these fixtures is through the test scripts:

```bash
# Run end-to-end tests with fixtures in headed mode
./scripts/run-e2e-tests.sh
```

Or using npm/pnpm directly:

```bash
# Run with fixtures
pnpm test:fixtures:headed

# Debug a specific test with fixtures
pnpm test:fixtures:headed --debug test=auth
```

## Procfile for Testing

A `Procfile.e2e` is provided in the root directory that sets up all the fixtures with the correct environment variables:

```
# Fixture servers
pds: cargo run --bin pds -- --port 3001
plc-directory: PDS_URL=http://localhost:3001 cargo run --bin plc-directory -- --port 3002
appview: AVATAR_CDN_URL=http://localhost:3003 cargo run --bin appview -- --port 3003

# Run the main app using the fixtures
server: PLC_DIRECTORY_URL=http://localhost:3002 APPVIEW_URL=http://localhost:3003 AVATAR_CDN_URL=http://localhost:3003 cargo run --bin pfp-blue
```

You can run this with `overmind`:

```bash
overmind start -f Procfile.e2e
```

## Custom Fixture Data

You can provide a JSON file with custom responses for the fixtures:

```bash
cargo run --bin pds -- --port 3001 --data fixtures/custom-data.json
```

## Authentication

The fixtures provide a mock user with the following credentials:

- Handle: `fixture-user.test`
- DID: `did:plc:abcdefg`

When testing authentication flows, enter `fixture-user.test` as the handle to log in with the fixture user.