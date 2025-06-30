from app import db
from uuid import uuid4
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

def generate_uuid():
    return str(uuid4())

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.String(), primary_key=True, default=generate_uuid)
    username = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), nullable=False)
    password = db.Column(db.Text())

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

    @classmethod
    def get_user_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    def save(self):
        db.session.add(self)
        db.session.commit()

class TokenBlocklist(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    jti = db.Column(db.String(), nullable=False)
    create_at = db.Column(db.DateTime(), default=datetime.utcnow)

    def save(self):
        db.session.add(self)
        db.session.commit()
