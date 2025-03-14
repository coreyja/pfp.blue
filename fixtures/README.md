# Fixtures for pfp.blue

This crate provides mock servers for the external web services that the pfp.blue application interacts with. These fixtures allow for reliable end-to-end testing without dependencies on external APIs.

## Available Fixtures

### 1. PDS (Personal Data Server)

Mock server for Bluesky's Personal Data Server, handling requests for profiles, blobs, and authentication.

```bash
cargo run --bin pds -- --port 3000
```

### 2. AppView

Mock server for Bluesky's AppView service, handling actor resolution, profiles, and searches.

```bash
cargo run --bin appview -- --port 3001
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

## Custom Fixture Data

You can provide a JSON file with custom responses for the fixtures:

```bash
cargo run --bin pds -- --port 3000 --data fixtures/custom-data.json
```

## Using in End-to-End Tests

To use these fixtures in end-to-end tests, start each fixture on a specific port and configure your application to point to these fixtures instead of the real services.

For example, you might run them in parallel:

```bash
cargo run --bin pds -- --port 3000 &
cargo run --bin appview -- --port 3001 &
cargo run --bin plc-directory -- --port 3002 &

# Run your tests against the fixtures
# ...

# Clean up the background processes when done
kill %1 %2 %3
```