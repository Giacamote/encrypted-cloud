import os
from flask import Blueprint, render_template, request, redirect, url_for, send_from_directory, flash
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from ecloud import db
from ecloud.models.file import File

files_bp = Blueprint("files", __name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@files_bp.route("/files")
@login_required
def list_files():
    user_files = File.query.filter_by(owner_id=current_user.id).all()
    return render_template("files.html", files=user_files)


@files_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("file")

        if not file:
            flash("No file selected", "danger")
            return redirect(url_for("files.upload"))

        filename = secure_filename(file.filename)
        stored_filename = f"{current_user.id}_{filename}"

        file_path = os.path.join(UPLOAD_FOLDER, stored_filename)
        file.save(file_path)

        # Save to DB
        new_file = File(
            original_filename=filename,
            stored_filename=stored_filename,
            owner_id=current_user.id
        )
        db.session.add(new_file)
        db.session.commit()

        flash("File uploaded successfully", "success")
        return redirect(url_for("files.list_files"))

    return render_template("upload.html")
    

@files_bp.route("/files/download/<int:file_id>")
@login_required
def download(file_id):
    f = File.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    return send_from_directory(UPLOAD_FOLDER, f.stored_filename, as_attachment=True)


@files_bp.route("/files/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    f = File.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()

    # Remove file from filesystem
    path = os.path.join(UPLOAD_FOLDER, f.stored_filename)
    if os.path.exists(path):
        os.remove(path)

    # Remove from db
    db.session.delete(f)
    db.session.commit()

    flash("File deleted.", "success")
    return redirect(url_for("files.list_files"))
