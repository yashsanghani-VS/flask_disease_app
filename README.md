# Flask Authentication API

A secure RESTful API built with Flask for user authentication and authorization.

## Features

- User registration and authentication
- JWT-based authentication
- Role-based access control
- Password hashing and security
- Token blacklisting
- Account locking for failed attempts
- CORS support
- Database migrations
- Error handling
- Logging

## Prerequisites

- Python 3.8+
- PostgreSQL
- pip

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd <repository-name>
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file in the root directory with the following variables:
```
FLASK_APP=run.py
FLASK_ENV=development
DATABASE_URL=sqlite:///app.db
<!-- DATABASE_URL=postgresql://username:password@localhost:5432/dbname -->
JWT_SECRET_KEY=your-secret-key
```

## Database Setup

1. Initialize the database:
```bash
flask db init
```

2. Create the initial migration:
```bash
flask db migrate -m "Initial migration"
```

3. Apply the migration:
```bash
flask db upgrade
```

## Running the Application

1. Start the development server:
```bash
flask run --port=8000
```

The API will be available at `http://localhost:8000`

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login and get JWT token
- `POST /api/auth/logout` - Logout and blacklist token
- `POST /api/auth/refresh` - Refresh JWT token

### Users
- `GET /api/users` - Get all users (admin only)
- `GET /api/users/<id>` - Get user by ID
- `PUT /api/users/<id>` - Update user
- `DELETE /api/users/<id>` - Delete user (admin only)

## Security Features

- Password hashing using Bcrypt
- JWT token authentication
- Role-based access control
- Account locking after failed attempts
- Token blacklisting
- CORS protection
- Input validation

## Error Handling

The API includes comprehensive error handling for:
- Authentication errors
- Authorization errors
- Validation errors
- Database errors
- Generic errors

## Logging

Application logs are stored in the `logs` directory:
- `flask_auth.log` - Main application log
- Log rotation with a maximum of 10 backup files

## Testing

To run tests:
```bash
pytest
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
