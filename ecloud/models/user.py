from ecloud.extensions import db
from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    # --- X25519 wrapping keys ---
    public_wrap_spki = db.Column(db.Text, nullable=False)
    private_wrap_spki = db.Column(db.Text, nullable=False)

    # --- Ed25519 signing keys ---
    public_sign_spki = db.Column(db.Text, nullable=False)
    private_sign_spki = db.Column(db.Text, nullable=False)

    # relationships
    files = db.relationship(
        "File",
        back_populates="owner",
        cascade="all, delete-orphan"
    )

    groups = db.relationship(
        "Group",
        secondary="group_members",
        back_populates="members"
    )
