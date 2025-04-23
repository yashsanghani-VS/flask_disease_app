# Flask JWT Authentication API

A professional Flask application with JWT authentication and PostgreSQL database.

## Features

- User registration and login with JWT
- Password hashing with Bcrypt
- PostgreSQL database integration
- RESTful API endpoints
- Proper error handling
- Environment configuration

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file in the root directory with the following variables:
```
DATABASE_URL=postgresql://username:password@localhost:5432/dbname
JWT_SECRET_KEY=your-secret-key
FLASK_APP=run.py
FLASK_ENV=development
```

4. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

5. Run the application:
```bash
flask run
```

## API Endpoints

- POST /api/auth/register - Register a new user
- POST /api/auth/login - Login and get JWT token
- GET /api/auth/me - Get current user information
- PUT /api/auth/me - Update user information
- POST /api/auth/refresh - Refresh JWT token
- POST /api/auth/logout - Logout and invalidate token

## Project Structure

```
.
├── app/
│   ├── __init__.py
│   ├── config.py
│   ├── models/
│   │   └── user.py
│   ├── routes/
│   │   └── auth.py
│   ├── schemas/
│   │   └── user.py
│   └── utils/
│       └── decorators.py
├── migrations/
├── .env
├── .gitignore
├── requirements.txt
└── run.py
```