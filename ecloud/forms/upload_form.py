from wtforms import SubmitField, SelectField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_wtf.file import FileField, FileRequired
from flask_wtf import FlaskForm
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "txt", "md", "zip", "csv"}
class UploadForm(FlaskForm):
    group_id = SelectField("Group", coerce=int, choices=[])
    file = FileField("File", validators=[FileRequired()])
    submit = SubmitField("Upload")
