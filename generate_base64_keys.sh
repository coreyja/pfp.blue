#!/bin/bash

echo "🔑 PFP.BLUE Base64 Key Generator"
echo "================================"
echo "This script will generate new EC keys and encode them as base64"
echo ""

# Generate EC private key
echo "Generating EC private key..."
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/ec_private.pem

# Generate public key from private key
echo "Generating public key..."
openssl ec -in /tmp/ec_private.pem -pubout -out /tmp/ec_public.pem

# Base64 encode the keys (without newlines in the base64 output)
echo "Encoding keys as base64..."
PRIVATE_KEY_BASE64=$(base64 -i /tmp/ec_private.pem | tr -d '\n')
PUBLIC_KEY_BASE64=$(base64 -i /tmp/ec_public.pem | tr -d '\n')


# Add the base64 encoded keys
echo "export OAUTH_PRIVATE_KEY='$PRIVATE_KEY_BASE64'"
echo "export OAUTH_PUBLIC_KEY='$PUBLIC_KEY_BASE64'"

# Clean up
rm -f /tmp/ec_private.pem /tmp/ec_public.pem
