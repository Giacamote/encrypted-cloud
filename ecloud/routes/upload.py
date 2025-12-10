import os
import uuid
from flask import Blueprint, request, redirect, url_for, flash, send_from_directory, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from ecloud.extensions import db
from ecloud.models.file import File

upload_bp = Blueprint("upload", __name__, url_prefix="")
UPLOAD_FOLDER = os.path.join(os.getcwd(), "instance", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@upload_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    file = request.files.get("file")
    group_id=request.form.get("group_id")
    if group_id == "": group_id = None #que sean nulos, no empty
    if not file:
        flash("No file selected.", "danger")
        return redirect(url_for("dashboard.dashboard"))

    # Normalize unsafe filenames
    original_filename = secure_filename(file.filename)
    if original_filename == "":
        flash("Invalid filename.", "danger")
        return redirect(url_for("dashboard.dashboard"))

    # Create a unique stored filename (avoid collisions)
    stored_filename = f"{uuid.uuid4().hex}_{original_filename}"
    upload_folder = os.path.join(os.getcwd(), "instance", "uploads")
    os.makedirs(upload_folder, exist_ok=True)
    save_path = os.path.join(upload_folder, stored_filename)

    # Save file to disk
    file.save(save_path)

    # Create new File row
    new_file = File(
        original_filename=original_filename,
        stored_filename=stored_filename,
        mimetype=file.mimetype,
        size=os.path.getsize(save_path),
        owner_id=current_user.id,
        group_id=group_id
    )
    db.session.add(new_file)
    db.session.commit()

    flash("File uploaded successfully.", "success")
    return redirect(url_for("dashboard.dashboard"))



# ---------------------------
#   DOWNLOAD FILE
# ---------------------------
@upload_bp.route("/download/<int:file_id>")
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)

    # Ensure user owns the file
    if file.owner_id != current_user.id:
        if file.group_id is None or current_user not in file.group.members:
            abort(403)

    return send_from_directory(
        UPLOAD_FOLDER,
        file.stored_filename,
        as_attachment=True,
        download_name=file.original_filename
    )


# ---------------------------
#   DELETE FILE
# ---------------------------
@upload_bp.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)

    # Prevent deleting files of other users
    if file.owner_id != current_user.id and file.group.owner_id != current_user.id:
        abort(403)
    
    file_path = os.path.join(UPLOAD_FOLDER, file.stored_filename)
    # Delete physical file
    try:
        os.remove(os.path.join(UPLOAD_FOLDER, file.stored_filename))
    except FileNotFoundError:
        pass  # file missing is fine

    # Delete DB entry
    db.session.delete(file)
    db.session.commit()

    flash("File deleted.", "success")
    return redirect(url_for("dashboard.dashboard"))