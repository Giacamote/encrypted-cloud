from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_wtf import FlaskForm
class LoginForm(FlaskForm):
    username=StringField(validators=[InputRequired(), Length(min=4, max =30)], render_kw={"placeholder": "Username"})
    password=PasswordField(validators=[InputRequired(), Length(min=4, max =30)], render_kw={"placeholder": "Password"})
    submit=SubmitField("Login")
