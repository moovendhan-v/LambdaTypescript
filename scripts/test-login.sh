#!/bin/bash

# Test script for login endpoint

echo "Testing login endpoint..."

# Note: SAM should be running for this test to work

# Test payload (use the user registered from test-register.sh)
PAYLOAD='{
  "email": "test@example.com",
  "password": "password123"
}'

echo "Sending request to login endpoint..."
echo "Payload: $PAYLOAD"

# Make the request
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  -w "\nStatus Code: %{http_code}\n"

echo ""
echo "Test completed."