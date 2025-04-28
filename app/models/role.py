from app import db
from datetime import datetime

class Role(db.Model):
    """Model for user roles."""
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship with users
    users = db.relationship('User', backref='role', lazy='dynamic')
    
    def __init__(self, name, description=None):
        self.name = name
        self.description = description
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
    
    @classmethod
    def get_by_name(cls, name):
        """Get role by name."""
        return cls.query.filter_by(name=name).first()
    
    @classmethod
    def create_default_roles(cls):
        """Create default roles if they don't exist."""
        roles = [
            ('admin', 'Administrator with full access'),
            ('user', 'Regular user with limited access')
        ]
        
        for name, description in roles:
            if not cls.get_by_name(name):
                role = cls(name=name, description=description)
                db.session.add(role)
        
        db.session.commit()