#!/bin/bash

# Generate EC private key
openssl ecparam -name prime256v1 -genkey -noout -out /tmp/private.pem

# Generate public key from private key
openssl ec -in /tmp/private.pem -pubout -out /tmp/public.pem

# Format keys for .envrc
PRIVATE_KEY=$(cat /tmp/private.pem | tr '\n' '~' | sed 's/~/\\n/g')
PUBLIC_KEY=$(cat /tmp/public.pem | tr '\n' '~' | sed 's/~/\\n/g')

# Check if .envrc exists
if [ -f .envrc ]; then
    echo "Updating existing .envrc file..."
    
    # Remove existing key exports if they exist
    grep -v "OAUTH_PRIVATE_KEY\|OAUTH_PUBLIC_KEY" .envrc > .envrc.new
    
    # Add the new keys
    echo "export OAUTH_PRIVATE_KEY='$PRIVATE_KEY'" >> .envrc.new
    echo "export OAUTH_PUBLIC_KEY='$PUBLIC_KEY'" >> .envrc.new
    
    # Replace the old file
    mv .envrc.new .envrc
else
    echo "Creating new .envrc file..."
    
    # Create a new .envrc with the keys
    echo "export OAUTH_PRIVATE_KEY='$PRIVATE_KEY'" > .envrc
    echo "export OAUTH_PUBLIC_KEY='$PUBLIC_KEY'" >> .envrc
fi

# Clean up
rm /tmp/private.pem /tmp/public.pem

echo "Keys have been set up in .envrc"
echo "Run 'direnv allow' to load the environment variables"