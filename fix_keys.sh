#!/bin/bash

echo "🔑 PFP.BLUE Key Fixer"
echo "======================"
echo "This script will check your OAuth keys and fix them if needed."
echo ""

# Function to check if a string contains proper PEM format
check_pem_format() {
    local key=$1
    local key_type=$2
    
    # Check if key contains actual newlines or escaped newlines
    if [[ $key == *"-----BEGIN"*"-----END"* ]]; then
        echo "✅ $key_type key appears to contain proper PEM format."
        return 0
    elif [[ $key == *"\\n"* && $key == *"-----BEGIN"* && $key == *"-----END"* ]]; then
        echo "⚠️  $key_type key contains escaped newlines (\\n). This is probably fine as they'll be converted."
        return 0
    else
        echo "❌ $key_type key does not appear to be in PEM format!"
        return 1
    fi
}

# Check if .envrc exists
if [ ! -f .envrc ]; then
    echo "❌ No .envrc file found. Creating a new one with fresh keys."
    echo "Creating new .envrc file and generating keys..."
    
    # Generate EC private key
    openssl ecparam -name prime256v1 -genkey -noout -out /tmp/private.pem
    
    # Generate public key from private key
    openssl ec -in /tmp/private.pem -pubout -out /tmp/public.pem
    
    # Format keys for .envrc
    PRIVATE_KEY=$(cat /tmp/private.pem | tr '\n' '~' | sed 's/~/\\n/g')
    PUBLIC_KEY=$(cat /tmp/public.pem | tr '\n' '~' | sed 's/~/\\n/g')
    
    # Create a new .envrc with the keys
    echo "export OAUTH_PRIVATE_KEY='$PRIVATE_KEY'" > .envrc
    echo "export OAUTH_PUBLIC_KEY='$PUBLIC_KEY'" >> .envrc
    echo "export OAUTH_CLIENT_SECRET='placeholder-client-secret'" >> .envrc
    
    # Clean up
    rm /tmp/private.pem /tmp/public.pem
    
    echo "✅ Created new .envrc with fresh keys."
    echo "Run 'direnv allow' to load the environment variables."
    exit 0
fi

# Read the current keys from .envrc
source .envrc 2>/dev/null

# Check if keys are set
if [ -z "$OAUTH_PRIVATE_KEY" ] || [ -z "$OAUTH_PUBLIC_KEY" ]; then
    echo "❌ One or both OAuth keys are missing from .envrc."
    
    # Ask if the user wants to generate new keys
    read -p "Would you like to generate new keys? (y/n): " generate_keys
    
    if [[ $generate_keys == "y" || $generate_keys == "Y" ]]; then
        echo "Generating new keys..."
        
        # Generate EC private key
        openssl ecparam -name prime256v1 -genkey -noout -out /tmp/private.pem
        
        # Generate public key from private key
        openssl ec -in /tmp/private.pem -pubout -out /tmp/public.pem
        
        # Format keys for .envrc
        PRIVATE_KEY=$(cat /tmp/private.pem | tr '\n' '~' | sed 's/~/\\n/g')
        PUBLIC_KEY=$(cat /tmp/public.pem | tr '\n' '~' | sed 's/~/\\n/g')
        
        # Update .envrc
        grep -v "OAUTH_PRIVATE_KEY\|OAUTH_PUBLIC_KEY" .envrc > .envrc.new || touch .envrc.new
        echo "export OAUTH_PRIVATE_KEY='$PRIVATE_KEY'" >> .envrc.new
        echo "export OAUTH_PUBLIC_KEY='$PUBLIC_KEY'" >> .envrc.new
        
        # Add client_secret if not present
        if [ -z "$OAUTH_CLIENT_SECRET" ]; then
            echo "export OAUTH_CLIENT_SECRET='placeholder-client-secret'" >> .envrc.new
        fi
        
        # Replace the old file
        mv .envrc.new .envrc
        
        # Clean up
        rm /tmp/private.pem /tmp/public.pem
        
        echo "✅ Added new keys to .envrc."
        echo "Run 'direnv allow' to load the environment variables."
        exit 0
    else
        echo "❌ Keys not generated. Please edit .envrc manually to add the missing keys."
        exit 1
    fi
fi

# Check the format of existing keys
private_key_ok=1
public_key_ok=1

check_pem_format "$OAUTH_PRIVATE_KEY" "Private" || private_key_ok=0
check_pem_format "$OAUTH_PUBLIC_KEY" "Public" || public_key_ok=0

# Convert escaped newlines to real newlines and test parsing
if [[ $private_key_ok -eq 1 && $public_key_ok -eq 1 ]]; then
    echo ""
    echo "Testing key parsing..."
    
    # Create test file with private key - using printf for reliable newline replacement
    printf "%b" "$OAUTH_PRIVATE_KEY" > /tmp/test_private.pem
    
    # Try to verify the private key
    if openssl ec -in /tmp/test_private.pem -noout 2>/dev/null; then
        echo "✅ Private key parsed successfully."
    else
        echo "❌ Failed to parse private key! It's in the right format but not a valid EC key."
        private_key_ok=0
    fi
    
    # Create test file with public key - using printf for reliable newline replacement
    printf "%b" "$OAUTH_PUBLIC_KEY" > /tmp/test_public.pem
    
    # Try to verify the public key
    if openssl ec -pubin -in /tmp/test_public.pem -noout 2>/dev/null; then
        echo "✅ Public key parsed successfully."
    else
        echo "❌ Failed to parse public key! It's in the right format but not a valid EC public key."
        public_key_ok=0
    fi
    
    # Clean up test files
    rm -f /tmp/test_private.pem /tmp/test_public.pem
fi

# If either key is not OK, ask to generate new keys
if [[ $private_key_ok -eq 0 || $public_key_ok -eq 0 ]]; then
    echo ""
    echo "⚠️  One or both keys are not in the correct format or are invalid."
    read -p "Would you like to generate new keys? (y/n): " generate_keys
    
    if [[ $generate_keys == "y" || $generate_keys == "Y" ]]; then
        echo "Generating new keys..."
        
        # Generate EC private key
        openssl ecparam -name prime256v1 -genkey -noout -out /tmp/private.pem
        
        # Generate public key from private key
        openssl ec -in /tmp/private.pem -pubout -out /tmp/public.pem
        
        # Format keys for .envrc
        PRIVATE_KEY=$(cat /tmp/private.pem | tr '\n' '~' | sed 's/~/\\n/g')
        PUBLIC_KEY=$(cat /tmp/public.pem | tr '\n' '~' | sed 's/~/\\n/g')
        
        # Update .envrc
        grep -v "OAUTH_PRIVATE_KEY\|OAUTH_PUBLIC_KEY" .envrc > .envrc.new
        echo "export OAUTH_PRIVATE_KEY='$PRIVATE_KEY'" >> .envrc.new
        echo "export OAUTH_PUBLIC_KEY='$PUBLIC_KEY'" >> .envrc.new
        
        # Replace the old file
        mv .envrc.new .envrc
        
        # Clean up
        rm /tmp/private.pem /tmp/public.pem
        
        echo "✅ Updated .envrc with new keys."
        echo "Run 'direnv allow' to load the environment variables."
    else
        echo "❌ Keys not updated. Manual fixing is required."
        exit 1
    fi
else
    echo ""
    echo "✅ Both keys appear to be valid. No changes needed."
fi