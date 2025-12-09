from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_wtf import FlaskForm
from ecloud.models.user import User
from ecloud.extensions import db
class RegisterForm(FlaskForm):
    username=StringField(validators=[InputRequired(), Length(min=4, max =30)], render_kw={"placeholder": "Username"})
    password=PasswordField(validators=[InputRequired(), Length(min=4, max =30)], render_kw={"placeholder": "Password"})
    submit=SubmitField("Register")
    def validate_username(self, username):
        existing_user_username=User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("That username is already in use! Choose another.")
