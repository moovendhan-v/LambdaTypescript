#!/bin/bash

set -e

echo "Setting up local development environment..."

# Load environment variables from .env file
if [ -f ".env" ]; then
    echo "Loading environment variables from .env file..."
    export $(grep -v '^#' .env | xargs)
else
    echo "Warning: .env file not found. Using default values."
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if SAM CLI is installed
if ! command -v sam > /dev/null 2>&1; then
    echo "Error: SAM CLI is not installed. Please install it and try again."
    exit 1
fi

# Install layer dependencies
echo "Installing layer dependencies..."
cd layers/common-layer/nodejs && npm install && cd ../../..
cd layers/sequelize-layer/nodejs && npm install && cd ../../..

# Build the project
echo "Building the project..."
npm run build

# Start the database
echo "Starting PostgreSQL database..."
docker-compose -f docker/docker-compose.yml up -d

# Wait for database to be ready
echo "Waiting for database to be ready..."
sleep 15

# Run database migrations
echo "Running database migrations..."
npm run db:migrate

# Seed the database
echo "Seeding the database..."
npm run db:seed

echo "Local setup complete!"
echo ""
echo "Environment variables loaded:"
echo "  ENVIRONMENT=$ENVIRONMENT"
echo "  DATABASE_HOST=$DATABASE_HOST"
echo "  DATABASE_PORT=$DATABASE_PORT"
echo "  DATABASE_NAME=$DATABASE_NAME"
echo "  DATABASE_USER=$DATABASE_USER"
echo "  JWT_SECRET=${JWT_SECRET:0:10}..."
echo "  JWT_EXPIRES_IN=$JWT_EXPIRES_IN"
echo ""
echo "To start the API locally, run:"
echo "npm run sam:local"
echo ""
echo "The API will be available at http://localhost:3000"
echo ""
echo "To test the register endpoint:"
echo "npm run test:register"