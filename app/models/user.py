from app import db
from datetime import datetime, timedelta
from marshmallow import Schema, fields, validate
from passlib.hash import argon2
from app.models.role import Role
from app.utils.error_handler import APIError

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    
    def __init__(self, email, password, first_name, last_name, role_name='user'):
        self.email = email
        self.password = password
        self.first_name = first_name
        self.last_name = last_name
        self.role = Role.get_by_name(role_name)
    
    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        # Use Argon2 for password hashing
        self.password_hash = argon2.hash(password)
    
    def verify_password(self, password):
        return argon2.verify(password, self.password_hash)
    
    def is_admin(self):
        return self.role.name == 'admin'
    
    def record_login_success(self):
        try:
            self.last_login = datetime.utcnow()
            self.failed_login_attempts = 0
            self.account_locked_until = None
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise APIError('Failed to record login success', 500)
    
    def record_login_failure(self):
        try:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:
                # Lock account for 30 minutes after 5 failed attempts
                self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise APIError('Failed to record login failure', 500)
    
    def is_account_locked(self):
        if self.account_locked_until:
            return datetime.utcnow() < self.account_locked_until
        return False
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_active': self.is_active,
            'role': self.role.name if self.role else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None
        }

class UserSchema(Schema):
    id = fields.Int(dump_only=True)
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=8))
    first_name = fields.Str(required=True, validate=validate.Length(min=1))
    last_name = fields.Str(required=True, validate=validate.Length(min=1))
    role = fields.Str(dump_only=True)
    is_active = fields.Bool(load_default=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)
    last_login = fields.DateTime(dump_only=True)
    
    class Meta:
        model = User
        load_instance = True