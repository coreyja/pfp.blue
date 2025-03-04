#!/bin/bash

echo "🔑 PFP.BLUE Base64 Key Generator"
echo "================================"
echo "This script will generate new EC keys and encode them as base64 for use in .envrc"
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

echo "Updating .envrc file..."
# Check if .envrc exists
if [ -f .envrc ]; then
    # Create backup
    cp .envrc .envrc.bak
    echo "Created backup of existing .envrc at .envrc.bak"
    
    # Extract other env vars
    grep -v "OAUTH_PRIVATE_KEY\|OAUTH_PUBLIC_KEY" .envrc > /tmp/new_envrc
else
    # Create new file
    touch /tmp/new_envrc
fi

# Add the base64 encoded keys
echo "export OAUTH_PRIVATE_KEY='$PRIVATE_KEY_BASE64'" >> /tmp/new_envrc
echo "export OAUTH_PUBLIC_KEY='$PUBLIC_KEY_BASE64'" >> /tmp/new_envrc

# Add client secret if not present
if ! grep -q "OAUTH_CLIENT_SECRET" /tmp/new_envrc; then
    echo "export OAUTH_CLIENT_SECRET='placeholder-client-secret'" >> /tmp/new_envrc
fi

# Replace with new one
mv /tmp/new_envrc .envrc

echo "Keys updated in .envrc"
echo ""
echo "✅ EC keys have been generated and base64 encoded in .envrc"
echo "🔄 Run 'direnv allow' to reload environment variables"

# Clean up
rm -f /tmp/ec_private.pem /tmp/ec_public.pem