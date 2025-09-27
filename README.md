# AWS Lambda User Management with TypeScript

A production-ready AWS Lambda application built with TypeScript, Sequelize ORM, and PostgreSQL for comprehensive user management.

## Features

- 🔐 JWT Authentication & Authorization
- 👥 User Management with Roles
- 📊 Profile Management
- 🗄️ PostgreSQL with Sequelize ORM
- 🚀 TypeScript with ES6+ syntax
- 🧪 Comprehensive Testing Suite
- 🐳 Docker for Local Development
- 📦 AWS SAM for Deployment

## Project Structure

```
src/
├── handlers/          # Lambda function handlers
├── services/          # Business logic layer
├── models/           # Sequelize models
├── repositories/     # Data access layer
├── utils/            # Utility functions
├── middleware/       # Express-like middleware
├── interfaces/       # TypeScript interfaces
├── types/           # TypeScript type definitions
└── config/          # Configuration files
```

## Getting Started

### Prerequisites

- Node.js 18+
- Docker & Docker Compose
- AWS SAM CLI
- PostgreSQL

### Installation

1. Clone the repository
2. Install dependencies: `npm install`
3. Set up environment: `cp .env.example .env`
4. Start local database: `npm run docker:up`
5. Set up database: `npm run db:setup`
6. Build the application: `npm run build`

### Local Development

```bash
# Start local API Gateway
npm run sam:local

# Run tests
npm test

# Type checking
npm run type-check
```

### Deployment

```bash
# Deploy to development
npm run sam:deploy:dev

# Deploy to production
npm run sam:deploy:prod
```

## API Endpoints

- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `GET /auth/verify` - Email verification
- `GET /users/me` - Get current user
- `GET /users` - Get all users (admin)
- `POST /users` - Create user (admin)
- `PUT /users/:id` - Update user
- `DELETE /users/:id` - Delete user (admin)

## License

MIT
