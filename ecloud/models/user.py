from ecloud.extensions import db
from flask_login import UserMixin
class User(db.Model, UserMixin):
    id=db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(30), nullable=False, unique=True)
    password=db.Column(db.String(80), nullable=False)
    files = db.relationship("File", back_populates="owner", cascade="all, delete-orphan")
