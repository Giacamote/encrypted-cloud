from ecloud.extensions import db
from datetime import datetime, timezone
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(260), nullable=False)
    stored_filename = db.Column(db.String(260), nullable=False, unique=True)
    mimetype = db.Column(db.String(120))
    size = db.Column(db.Integer)
    upload_time = db.Column(db.DateTime,default=lambda: datetime.now(timezone.utc))
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    owner = db.relationship("User", back_populates="files")
