from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_wtf import FlaskForm
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt", "md", "zip", "csv"}
class UploadForm(FlaskForm):
    file = FileField(validators=[
        FileRequired()
    ])
    submit = SubmitField("Upload")
