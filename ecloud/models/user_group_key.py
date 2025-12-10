# ecloud/models/user_group_key.py
from ecloud.extensions import db

class UserGroupKey(db.Model):
    __tablename__ = "user_group_key"
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("group.id"), nullable=False)

    #SPKI (base64) pks
    public_wrap_spki = db.Column(db.Text, nullable=False)# pk RSA-OAEP
    public_sign_spki = db.Column(db.Text, nullable=False)# pk de firma ECDSA

    #relations
    user = db.relationship("User", backref="group_keys")
    group = db.relationship("Group", backref="user_keys")

    __table_args__ = (db.UniqueConstraint("user_id", "group_id", name="_user_group_uc"),)
