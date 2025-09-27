#!/bin/bash

echo "Setting up local database..."

# Start Docker containers
docker-compose -f docker/docker-compose.yml up -d

# Wait for database to be ready
echo "Waiting for database to be ready..."
sleep 10

# Run migrations
npm run db:migrate

# Seed data
npm run db:seed

echo "Local database setup complete!"
