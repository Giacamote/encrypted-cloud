from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length

class CreateGroupForm(FlaskForm):
    groupname = StringField(
        "Group Name",
        validators=[
            DataRequired(),
            Length(min=3, max=30, message="Group name must be between 3 and 30 characters.")
        ]
    )
    submit = SubmitField("Create Group")
