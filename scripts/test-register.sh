#!/bin/bash

# Test script for register endpoint

echo "Testing register endpoint..."

# Note: SAM should be running for this test to work

# Test payload
PAYLOAD='{
  "email": "test@example.com",
  "password": "password123",
  "firstName": "Test",
  "lastName": "User"
}'

echo "Sending request to register endpoint..."
echo "Payload: $PAYLOAD"

# Make the request
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD" \
  -w "\nStatus Code: %{http_code}\n"

echo ""
echo "Test completed."