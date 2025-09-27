#!/bin/bash

# deploy-sam-app.sh
# Script to build and deploy an AWS SAM application using .samconfig.toml

# Exit on any error
set -e

# Default environment
CONFIG_ENV=${1:-dev}  # Use first argument or default to 'dev'

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to print error and exit
error_exit() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

# Function to print success message
success() {
    echo -e "${GREEN}$1${NC}"
}

# Step 1: Build TypeScript code
echo "Building TypeScript code..."
if ! npm run build; then
    error_exit "Failed to build TypeScript code"
fi
success "TypeScript build completed"

# Step 2: Run sam build
echo "Running sam build for environment: $CONFIG_ENV..."
if ! sam build --config-file samconfig.toml --config-env "$CONFIG_ENV"; then
    error_exit "sam build failed"
fi
success "SAM build completed"

# Step 3: Deploy the stack
echo "Deploying stack for environment: $CONFIG_ENV..."
if ! sam deploy --config-file samconfig.toml --config-env "$CONFIG_ENV" --no-fail-on-empty-changeset; then
    error_exit "sam deploy failed"
fi
success "Deployment completed successfully"

# Step 4: Output API URL
STACK_NAME=$(grep 'stack_name' samconfig.toml | grep -A1 "\[$CONFIG_ENV.deploy.parameters\]" | tail -n1 | cut -d'"' -f2)
REGION=$(grep 'region' samconfig.toml | grep -A1 "\[$CONFIG_ENV.deploy.parameters\]" | tail -n1 | cut -d'"' -f2)
echo "Retrieving API URL for stack: $STACK_NAME..."
API_URL=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --region "$REGION" \
    --query 'Stacks[0].Outputs[?OutputKey==`ApiUrl`].OutputValue' \
    --output text)
if [ -n "$API_URL" ]; then
    success "API URL: $API_URL"
else
    echo "Warning: Could not retrieve API URL"
fi

exit 0