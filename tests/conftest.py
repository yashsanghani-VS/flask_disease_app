import pytest
from app import create_app, db
from app.models.role import Role
from app.models.user import User
from app.models.token import TokenBlacklist

@pytest.fixture(scope='session')
def app():
    """Create application for the tests."""
    app = create_app('testing')
    
    # Create the database and load test data
    with app.app_context():
        db.create_all()
        Role.create_default_roles()
        
        # Create admin user
        admin_role = Role.query.filter_by(name='admin').first()
        admin = User(
            email='admin@example.com',
            password='Admin@123',
            first_name='Admin',
            last_name='User',
            role=admin_role
        )
        db.session.add(admin)
        db.session.commit()
    
    yield app
    
    # Clean up
    with app.app_context():
        db.session.remove()
        db.drop_all()

@pytest.fixture(scope='function')
def client(app):
    """Create a test client for the app."""
    return app.test_client()

@pytest.fixture(scope='function')
def runner(app):
    """Create a test CLI runner for the app."""
    return app.test_cli_runner() 