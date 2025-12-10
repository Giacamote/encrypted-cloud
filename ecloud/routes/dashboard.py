from flask import Blueprint, render_template
from flask_login import login_required, current_user
from ecloud.forms.upload_form import UploadForm
from ecloud.models.file import File
dashboard_bp = Blueprint("dashboard", __name__)

@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    upload_form = UploadForm()
    user_groups = current_user.groups

    # Files in groups where the user is a member
    files_by_group = {}
    for group in user_groups:
        # Only files of this group
        group_files = File.query.filter_by(group_id=group.id).all()
        files_by_group[group] = group_files

    # Files with no group, owned by current user
    user_files_no_group = File.query.filter_by(owner_id=current_user.id, group_id=None).all()

    # Populate dropdown
    upload_form.group_id.choices = [(g.id, g.groupname) for g in user_groups]

    return render_template(
        "dashboard.html",
        user=current_user,
        upload_form=upload_form,
        user_groups=user_groups,
        files_by_group=files_by_group,
        user_files_no_group=user_files_no_group
    )
@dashboard_bp.route("/")
def home():
    return render_template("home.html", user=current_user)
