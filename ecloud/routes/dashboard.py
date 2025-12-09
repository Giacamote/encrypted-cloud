from flask import Blueprint, render_template
from flask_login import login_required, current_user
from ecloud.forms.upload_form import UploadForm

dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    upload_form = UploadForm()
    user_files = current_user.files
    return render_template("dashboard.html", 
                           user=current_user, 
                           upload_form=upload_form, 
                           files=user_files)

@dashboard_bp.route("/")
def home():
    return render_template("home.html", user=current_user)
