from ecloud.extensions import db
group_members = db.Table(
    "group_members",
    db.Column("group_id", db.Integer, db.ForeignKey("group.id"), primary_key=True),
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True)
)

class Group(db.Model):
    __tablename__ = "group"

    id = db.Column(db.Integer, primary_key=True)
    groupname = db.Column(db.String(50), unique=True, nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    owner = db.relationship("User", backref="owned_groups")
    #members: many to many
    members = db.relationship(
        "User",
        secondary=group_members,
        backref=db.backref("groups", lazy="dynamic"),
        lazy="dynamic"
    )
    files = db.relationship("File", backref="group", lazy=True)

    def __repr__(self):
        return f"<Group {self.groupname}>"
