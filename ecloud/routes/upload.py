import os
import uuid
from flask import Blueprint, request, redirect, url_for, flash, send_from_directory, abort
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from ecloud.extensions import db
from ecloud.models.file import File
from ecloud.models.group import Group
from ecloud.models.wrapped_key import WrappedKey
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


import os
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def wrap_key_for_user(user_public_wrap_spki: str, file_key: bytes) -> dict:
    """
    Encrypt the symmetric file_key using the user's X25519 public key.

    Returns a dict with ephemeral public key + AESGCM components.
    """
    # Load user's public key (they must store SPKI base64 or PEM)
    public_key = serialization.load_pem_public_key(
        user_public_wrap_spki.encode()
    )
    if not isinstance(public_key, X25519PublicKey):
        raise ValueError("User's wrapping key is not X25519")

    # 1. Generate ephemeral keypair
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key()

    # 2. Perform ECDH
    shared_secret = eph_priv.exchange(public_key)

    # 3. Derive AES-256-GCM key using HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file-key-wrap"
    ).derive(shared_secret)

    # 4. Encrypt (wrap) the file_key using AES-GCM
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)

    ciphertext = aesgcm.encrypt(iv, file_key, None)  # GCM includes auth tag automatically

    # 5. Export ephemeral pubkey (SPKI PEM) and AES bundle
    eph_pub_pem = eph_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return {
        "ephemeral_public": eph_pub_pem.decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }
def unwrap_file_key(user_private_wrap_pkcs8: str, wrapped: dict) -> bytes:
    """
    User loads their X25519 private key and unwraps the AES-wrapped file_key.
    """
    # Load user's private key
    private_key = serialization.load_pem_private_key(
        user_private_wrap_pkcs8.encode(),
        password=None
    )
    if not isinstance(private_key, X25519PrivateKey):
        raise ValueError("User's wrapping key is not X25519")

    # Load ephemeral pubkey from sender
    eph_pub = serialization.load_pem_public_key(
        wrapped["ephemeral_public"].encode()
    )

    if not isinstance(eph_pub, X25519PublicKey):
        raise ValueError("Ephemeral key is not X25519")

    # 1. ECDH
    shared_secret = private_key.exchange(eph_pub)

    # 2. Derive same AESGCM key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file-key-wrap"
    ).derive(shared_secret)

    # 3. Decrypt file key
    aesgcm = AESGCM(aes_key)
    iv = base64.b64decode(wrapped["iv"])
    ciphertext = base64.b64decode(wrapped["ciphertext"])

    file_key = aesgcm.decrypt(iv, ciphertext, None)

    return file_key

upload_bp = Blueprint("upload", __name__, url_prefix="")
UPLOAD_FOLDER = os.path.join(os.getcwd(), "instance", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@upload_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload_file():
    file = request.files.get("file")
    group_id = request.form.get("group_id") or None

    if not file:
        flash("No file selected.", "danger")
        return redirect(url_for("dashboard.dashboard"))

    original_filename = secure_filename(file.filename)
    if original_filename == "":
        flash("Invalid filename.", "danger")
        return redirect(url_for("dashboard.dashboard"))

    stored_filename = f"{uuid.uuid4().hex}_{original_filename}"
    upload_folder = os.path.join(os.getcwd(), "instance", "uploads")
    os.makedirs(upload_folder, exist_ok=True)
    save_path = os.path.join(upload_folder, stored_filename)

    file_bytes = file.read()

    # ======================
    # 1. Generate AES key
    # ======================
    aes_key = os.urandom(32)  # AES-256

    # ======================
    # 2. Encrypt file
    # ======================
    iv = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, file_bytes, None)

    # save encrypted file to disk
    with open(save_path, "wb") as f:
        f.write(ciphertext)

    # ======================
    # 3. Sign ciphertext
    # ======================
    sign_priv = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(current_user.signing_private_key)
    )
    signature = sign_priv.sign(ciphertext)

    # ======================
    # 4. Create DB File row
    # ======================
    new_file = File(
        original_filename=original_filename,
        stored_filename=stored_filename,
        mimetype=file.mimetype,
        size=len(ciphertext),
        owner_id=current_user.id,
        group_id=group_id,
        iv_b64=base64.b64encode(iv).decode(),
        signature_b64=base64.b64encode(signature).decode()
    )

    db.session.add(new_file)
    db.session.flush()  # get new_file.id

    # ======================
    # 5. Wrap AES key
    # ======================

    if group_id:
        group = Group.query.get(group_id)
        for member in group.members:
            wrapped = wrap_key_for_user(aes_key, member)
            db.session.add(WrappedKey(
                file_id=new_file.id,
                user_id=member.id,
                group_id=group_id,
                wrapped_key_b64=wrapped
            ))
    else:
        # personal file → wrap only for owner
        wrapped = wrap_key_for_user(aes_key, current_user)
        db.session.add(WrappedKey(
            file_id=new_file.id,
            user_id=current_user.id,
            group_id=None,
            wrapped_key_b64=wrapped
        ))

    db.session.commit()
    flash("Encrypted file uploaded successfully!", "success")
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