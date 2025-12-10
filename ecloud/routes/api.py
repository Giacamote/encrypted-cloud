# ecloud/routes/api.py
import os, uuid, json, base64
from flask import Blueprint, request, jsonify, url_for, abort, current_app, send_file
from flask_login import login_required, current_user
from ecloud.extensions import db
from ecloud.models.file import File
from ecloud.models.file_key import FileKey
from ecloud.models.group import Group
from ecloud.models.user import User

api_bp = Blueprint("api", __name__, url_prefix="/api")

UPLOAD_DIR = os.path.join(os.getcwd(), "instance", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@api_bp.route("/upload_encrypted", methods=["POST"])
@login_required
def upload_encrypted():
    # expecting multipart/form-data:
    # - cipherfile (file)
    # - original_filename (str)
    # - mimetype (str)
    # - iv_b64 (str)
    # - signature_b64 (str)
    # - group_id (str or empty)
    # - wrapped_keys (JSON string) -> [{user_id, wrapped_b64}, ...]
    cipherfile = request.files.get("cipherfile")
    if cipherfile is None:
        return jsonify({"error":"missing cipherfile"}), 400

    original_filename = request.form.get("original_filename") or cipherfile.filename
    mimetype = request.form.get("mimetype") or cipherfile.mimetype or ""
    iv_b64 = request.form.get("iv_b64")
    signature_b64 = request.form.get("signature_b64")
    group_id = request.form.get("group_id") or None
    wrapped_keys_json = request.form.get("wrapped_keys") or "[]"

    # validate minimal fields
    if iv_b64 is None or signature_b64 is None:
        return jsonify({"error":"missing iv or signature"}), 400

    try:
        wrapped_keys = json.loads(wrapped_keys_json)
    except Exception:
        wrapped_keys = []

    # permission: if group_id provided, ensure uploader is a member of that group
    if group_id:
        group = Group.query.get(group_id)
        if not group:
            return jsonify({"error":"group not found"}), 404
        if current_user not in group.members:
            return jsonify({"error":"not a group member"}), 403
    else:
        group = None

    # save ciphertext
    stored_filename = f"{uuid.uuid4().hex}_{secure_filename(original_filename)}"
    save_path = os.path.join(UPLOAD_DIR, stored_filename)
    cipherfile.save(save_path)

    # create File row
    new_file = File(
        original_filename=original_filename,
        stored_filename=stored_filename,
        mimetype=mimetype,
        size=os.path.getsize(save_path),
        iv_b64=iv_b64,
        signature_b64=signature_b64,
        owner_id=current_user.id,
        group_id=group.id if group else None
    )
    db.session.add(new_file)
    db.session.flush()  # get new_file.id without commit

    # create FileKey rows for each wrapped key
    for wk in wrapped_keys:
        try:
            rid = int(wk.get("user_id"))
            wrapped_b64 = wk.get("wrapped_b64")
            if not wrapped_b64:
                continue
            fk = FileKey(file_id=new_file.id, target_user_id=rid, wrapped_key_b64=wrapped_b64)
            db.session.add(fk)
        except Exception:
            # ignore malformed entries
            continue

    db.session.commit()

    return jsonify({"status":"ok", "file_id": new_file.id}), 201


# ---------------------------
# Download: meta for a file (wrapped key for current user + owner public signing key)
# ---------------------------
@api_bp.route("/file/<int:file_id>/meta", methods=["GET"])
@login_required
def file_meta(file_id):
    f = File.query.get_or_404(file_id)

    # permission: owner or member of group
    if f.owner_id != current_user.id:
        if f.group_id is None or current_user not in f.group.members:
            return jsonify({"error":"forbidden"}), 403

    # find wrapped key for current user
    fk = FileKey.query.filter_by(file_id=f.id, target_user_id=current_user.id).first()
    wrapped_b64 = fk.wrapped_key_b64 if fk else None

    return jsonify({
        "cipher_url": url_for("api.download_cipher", file_id=f.id, _external=True),
        "iv_b64": f.iv_b64,
        "signature_b64": f.signature_b64,
        "owner_id": f.owner_id,
        "owner_public_sign_spki": f.owner.public_sign_spki,
        "wrapped_b64": wrapped_b64,
        "original_filename": f.original_filename,
        "mimetype": f.mimetype
    })


# ---------------------------
# Serve raw ciphertext bytes (NOT decrypted)
# ---------------------------
from werkzeug.utils import secure_filename
@api_bp.route("/file/<int:file_id>/cipher", methods=["GET"])
@login_required
def download_cipher(file_id):
    f = File.query.get_or_404(file_id)
    # permission check (same as above)
    if f.owner_id != current_user.id:
        if f.group_id is None or current_user not in f.group.members:
            abort(403)
    path = os.path.join(UPLOAD_DIR, f.stored_filename)
    if not os.path.exists(path):
        abort(404)
    # Return raw bytes (no as_attachment, client will decrypt and trigger download)
    return send_file(path, mimetype=f.mimetype, as_attachment=False)
