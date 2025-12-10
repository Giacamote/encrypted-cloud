# ecloud/models/file_key.py
from ecloud.extensions import db

class FileKey(db.Model):
    __tablename__ = "file_key"
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"), nullable=False)
    target_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    wrapped_key_b64 = db.Column(db.Text, nullable=False)#clave AES encriptada con la pk de un usuario objetivo RSA

    file = db.relationship("File", backref="wrapped_keys")
    target = db.relationship("User", backref="file_keys")
