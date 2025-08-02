# HTPI Authentication Service

Central authentication service for all HTPI portals.

## Features

- JWT-based authentication
- Multi-portal support (admin, customer)
- User role management
- Token verification and refresh
- NATS-based communication

## Architecture

This service handles authentication for:
- Admin Portal: System administrators
- Customer Portal: Tenant users with specific access

## NATS Subscriptions

- `htpi.auth.login` - Handle login requests
- `htpi.auth.verify` - Verify JWT tokens
- `htpi.auth.refresh` - Refresh JWT tokens

## Response Channels

- `admin.auth.response.*` - Admin portal responses
- `customer.auth.response.*` - Customer portal responses

## Environment Variables

```bash
NATS_URL=nats://localhost:4222
JWT_SECRET=your-jwt-secret-key
JWT_EXPIRATION_HOURS=24
```

## Running Locally

```bash
pip install -r requirements.txt
python app.py
```

## Docker Deployment

```bash
docker build -t htpi-auth-service .
docker run -e NATS_URL=nats://host.docker.internal:4222 htpi-auth-service
```