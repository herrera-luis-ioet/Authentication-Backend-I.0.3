# Authentication Backend

A secure authentication system built with Flask and JWT tokens.

## Features

- User registration with password hashing
- Login with JWT token generation
- Token refresh functionality
- Protected route decorator
- Rate limiting
- Security headers
- Input validation

## API Endpoints

### POST /auth/register
Register a new user.

**Request Body:**
```json
{
    "username": "user123",
    "password": "SecurePass123!"
}
```

**Response:**
```json
{
    "message": "User created successfully",
    "user": {
        "username": "user123"
    }
}
```

### POST /auth/login
Login and receive JWT tokens.

**Request Body:**
```json
{
    "username": "user123",
    "password": "SecurePass123!"
}
```

**Response:**
```json
{
    "access_token": "eyJ0eXAi...",
    "refresh_token": "eyJ0eXAi..."
}
```

### POST /auth/refresh
Refresh access token using refresh token.

**Headers:**
```
Authorization: Bearer <refresh_token>
```

**Response:**
```json
{
    "access_token": "eyJ0eXAi...",
    "refresh_token": "eyJ0eXAi..."
}
```

### GET /auth/protected
Example protected route (requires valid access token).

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
    "message": "Access granted",
    "user": {
        "username": "user123"
    }
}
```

## Security Features

1. Password Requirements:
   - Minimum 8 characters
   - At least one uppercase letter
   - At least one lowercase letter
   - At least one number
   - At least one special character

2. Username Requirements:
   - 3-32 characters
   - Only letters, numbers, underscores, and hyphens

3. Rate Limiting:
   - Registration: 5 requests per minute
   - Login: 10 requests per minute
   - Token refresh: 10 requests per minute
   - Global: 200 requests per day, 50 per hour

4. Security Headers:
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - X-XSS-Protection: 1; mode=block
   - Strict-Transport-Security: max-age=31536000; includeSubDomains

5. JWT Token Configuration:
   - Access token expiration: 15 minutes
   - Refresh token expiration: 30 days
   - Secure algorithm: HS256

## Environment Variables

- `SECRET_KEY`: Flask secret key
- `JWT_SECRET_KEY`: Secret key for JWT token generation
- `DATABASE_URL`: Database connection URL
- `REDIS_URL`: Redis URL for rate limiting in production (optional)

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables:
```bash
export SECRET_KEY="your-secret-key"
export JWT_SECRET_KEY="your-jwt-secret"
export DATABASE_URL="your-database-url"
```

3. Run the application:
```bash
flask run
```

## Testing

Run tests using pytest:
```bash
python -m pytest tests/
```