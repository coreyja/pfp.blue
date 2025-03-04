#!/bin/bash

echo "🔬 PFP.BLUE Key Diagnostic Tool"
echo "==============================="
echo "This script will diagnose issues with your OAuth keys."
echo ""

# Load environment variables
if [ -f .envrc ]; then
    source .envrc
else
    echo "❌ No .envrc file found."
    exit 1
fi

# Check if keys are set
if [ -z "$OAUTH_PRIVATE_KEY" ]; then
    echo "❌ OAUTH_PRIVATE_KEY is not set in .envrc."
    exit 1
fi

if [ -z "$OAUTH_PUBLIC_KEY" ]; then
    echo "❌ OAUTH_PUBLIC_KEY is not set in .envrc."
    exit 1
fi

echo "✅ Found keys in .envrc"
echo ""

# Function to check if the key is in valid PEM format
check_pem_format() {
    local key="$1"
    local key_type="$2"
    
    echo "🔍 Analyzing $key_type key..."
    
    # Check if it has begin/end markers
    if [[ "$key" != *"-----BEGIN"* || "$key" != *"-----END"* ]]; then
        echo "❌ $key_type key is missing PEM markers (-----BEGIN/-----END)"
        return 1
    fi
    
    # Check for escaped newlines
    if [[ "$key" == *"\\n"* ]]; then
        echo "✓ $key_type key contains escaped newlines (\\n)"
        
        # Try to write the key with real newlines
        echo -e "$key" > /tmp/${key_type}_key.pem
    else
        echo "❓ $key_type key doesn't contain escaped newlines, trying as-is"
        echo "$key" > /tmp/${key_type}_key.pem
    fi
    
    # Try to parse the key with OpenSSL
    if [[ "$key_type" == "private" ]]; then
        if ! openssl ec -in /tmp/${key_type}_key.pem -noout 2>/dev/null; then
            echo "❌ OpenSSL couldn't parse the $key_type key. Here's the error:"
            openssl ec -in /tmp/${key_type}_key.pem -noout 2>&1 | sed 's/^/    /'
            return 1
        fi
    else
        if ! openssl ec -pubin -in /tmp/${key_type}_key.pem -noout 2>/dev/null; then
            echo "❌ OpenSSL couldn't parse the $key_type key. Here's the error:"
            openssl ec -pubin -in /tmp/${key_type}_key.pem -noout 2>&1 | sed 's/^/    /'
            return 1
        fi
    fi
    
    echo "✅ $key_type key is valid and can be parsed by OpenSSL"
    return 0
}

# Create a correctly formatted version of keys
create_fixed_key() {
    local key="$1"
    local key_type="$2"
    
    # Create a new key with the correct format
    echo "🔧 Creating new $key_type key..."
    
    if [[ "$key_type" == "private" ]]; then
        openssl ecparam -name prime256v1 -genkey -noout -out /tmp/new_${key_type}.pem
    else
        openssl ec -in /tmp/new_private.pem -pubout -out /tmp/new_${key_type}.pem
    fi
    
    # Format for .envrc (escaped newlines)
    local formatted_key
    formatted_key=$(cat /tmp/new_${key_type}.pem | tr '\n' '~' | sed 's/~/\\n/g')
    
    echo "$formatted_key"
}

# Test the keys
private_key_ok=0
public_key_ok=0

check_pem_format "$OAUTH_PRIVATE_KEY" "private" && private_key_ok=1
check_pem_format "$OAUTH_PUBLIC_KEY" "public" && public_key_ok=1

echo ""
if [[ $private_key_ok -eq 1 && $public_key_ok -eq 1 ]]; then
    echo "✅ Both keys appear to be valid!"
    rm -f /tmp/private_key.pem /tmp/public_key.pem
    exit 0
fi

echo "⚠️  One or both keys are invalid. Would you like to generate new keys? (y/n)"
read -r generate_keys

if [[ "$generate_keys" == "y" || "$generate_keys" == "Y" ]]; then
    # Generate new keys
    new_private_key=$(create_fixed_key "" "private")
    new_public_key=$(create_fixed_key "" "public")
    
    # Create new .envrc
    echo "🔧 Updating .envrc with new keys..."
    
    # Extract other env vars
    grep -v "OAUTH_PRIVATE_KEY\|OAUTH_PUBLIC_KEY" .envrc > /tmp/new_envrc
    
    # Add new keys
    echo "export OAUTH_PRIVATE_KEY='$new_private_key'" >> /tmp/new_envrc
    echo "export OAUTH_PUBLIC_KEY='$new_public_key'" >> /tmp/new_envrc
    
    # Create backup of old .envrc
    cp .envrc .envrc.bak
    
    # Replace with new one
    mv /tmp/new_envrc .envrc
    
    echo "✅ Keys have been updated in .envrc (old version saved as .envrc.bak)"
    echo "🔄 Run 'direnv allow' to reload environment variables"
    
    # Clean up
    rm -f /tmp/new_private.pem /tmp/new_public.pem /tmp/private_key.pem /tmp/public_key.pem
else
    echo "❌ No changes made. Please fix the keys manually or run this script again to generate new keys."
fi