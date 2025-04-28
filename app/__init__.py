from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import os
from dotenv import load_dotenv
from app.utils.logger import logger

# Load environment variables
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()
bcrypt = Bcrypt()

def create_app(config_name='default'):
    """Create and configure the Flask application."""
    logger.info("Initializing Flask application...")
    app = Flask(__name__)
    
    # Load configuration
    from app.config import config
    app.config.from_object(config[config_name])
    logger.info("Configuration loaded")
    
    # Initialize extensions with app
    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    CORS(app)
    logger.info("Extensions initialized")
    
    # Register API blueprint
    from app.api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    logger.info("API blueprint registered")
    
    # Register error handlers
    from app.utils.error_handler import (
        handle_api_error,
        handle_validation_error,
        handle_http_error,
        handle_generic_error,
        handle_integrity_error,
        handle_jwt_error,
        APIError
    )
    from werkzeug.exceptions import HTTPException
    from marshmallow import ValidationError
    from sqlalchemy.exc import IntegrityError
    from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError, WrongTokenError, RevokedTokenError, FreshTokenRequired
    
    # Register specific error handlers
    app.register_error_handler(APIError, handle_api_error)
    app.register_error_handler(ValidationError, handle_validation_error)
    app.register_error_handler(HTTPException, handle_http_error)
    app.register_error_handler(IntegrityError, handle_integrity_error)
    
    # Register JWT error handlers
    app.register_error_handler(NoAuthorizationError, handle_jwt_error)
    app.register_error_handler(InvalidHeaderError, handle_jwt_error)
    app.register_error_handler(WrongTokenError, handle_jwt_error)
    app.register_error_handler(RevokedTokenError, handle_jwt_error)
    app.register_error_handler(FreshTokenRequired, handle_jwt_error)
    
    # Register generic error handler last
    app.register_error_handler(Exception, handle_generic_error)
    
    # Initialize database and create default roles
    with app.app_context():
        logger.info("Creating database tables...")
        db.create_all()
        
        logger.info("Creating default roles...")
        from app.models.role import Role
        Role.create_default_roles()
        
        logger.info("Creating admin user...")
        create_admin_user()
        
        logger.info("Cleaning up expired tokens...")
        from app.models.token import TokenBlacklist
        TokenBlacklist.cleanup_expired()
    
    logger.info("Application initialization complete")
    return app

@jwt.user_identity_loader
def user_identity_lookup(user):
    """Convert user object to identity."""
    return str(user.id) if user else None

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    """Convert identity to user object."""
    from app.models.user import User
    identity = jwt_data["sub"]
    return User.query.filter_by(id=int(identity)).one_or_none()

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_data):
    """Handle expired token."""
    logger.warning("Token expired")
    return jsonify({
        'status': 'error',
        'message': 'Token has expired. Please login again.',
        'status_code': 401
    }), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    """Handle invalid token."""
    logger.warning(f"Invalid token: {str(error)}")
    return jsonify({
        'status': 'error',
        'message': 'Invalid token. Please login again.',
        'status_code': 401
    }), 401

@jwt.unauthorized_loader
def unauthorized_callback(error):
    """Handle unauthorized access."""
    logger.warning("Missing Authorization Header")
    return jsonify({
        'status': 'error',
        'message': 'Missing Authorization Header. Please provide a valid token.',
        'status_code': 401
    }), 401

@jwt.needs_fresh_token_loader
def needs_fresh_token_callback(jwt_header, jwt_data):
    """Handle fresh token requirement."""
    logger.warning("Fresh token required")
    return jsonify({
        'status': 'error',
        'message': 'Fresh token required. Please login again.',
        'status_code': 401
    }), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_data):
    """Handle revoked token."""
    logger.warning("Token has been revoked")
    return jsonify({
        'status': 'error',
        'message': 'Token has been revoked. Please login again.',
        'status_code': 401
    }), 401

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    """Check if token is in blocklist."""
    try:
        from app.models.token import TokenBlacklist
        jti = jwt_payload["jti"]
        return TokenBlacklist.is_blacklisted(jti)
    except Exception as e:
        logger.error(f"Error checking token blacklist: {str(e)}")
        return False

def create_admin_user():
    """Create default admin user if it doesn't exist."""
    from app.models.user import User
    from app.models.role import Role
    
    try:
        logger.info("Starting admin user creation process...")
        
        # Use hardcoded values for testing
        admin_email = "admin@example.com"
        admin_password = "Admin@123"
        admin_first_name = "Admin"
        admin_last_name = "User"
        
        logger.info(f"Attempting to create admin user with email: {admin_email}")
        
        # Check if admin user already exists
        existing_admin = User.query.filter_by(email=admin_email).first()
        if existing_admin:
            logger.info(f"Admin user with email {admin_email} already exists")
            return
        
        logger.info("Creating new admin user...")
        
        # Create admin user
        admin_user = User(
            email=admin_email,
            password=admin_password,
            first_name=admin_first_name,
            last_name=admin_last_name,
            role_name="admin"
        )
        
        logger.info("Adding admin user to database...")
        db.session.add(admin_user)
        db.session.commit()
        
        logger.info(f"Successfully created admin user: {admin_email}")
        
    except Exception as e:
        logger.error(f"Error creating admin user: {str(e)}")
        db.session.rollback()