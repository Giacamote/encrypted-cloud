# ecloud/routes/group_keys.py
from flask import Blueprint, request, jsonify, abort
from flask_login import login_required, current_user
from ecloud.extensions import db
from ecloud.models.user_group_key import UserGroupKey
from ecloud.models.group import Group
from ecloud.models.user import User

keys_bp = Blueprint("group_keys", __name__, url_prefix="/group_keys")

@keys_bp.route("/<int:group_id>/upload", methods=["POST"])
@login_required
def upload_group_keys(group_id):
    # Only members (or the group owner) should upload keys for (user,group)
    group = Group.query.get_or_404(group_id)
    # optionally ensure current_user is a member of group before accepting keys
    if current_user not in group.members:
        return jsonify({"error": "not a group member"}), 403

    data = request.json
    pub_wrap = data.get("public_wrap_spki")
    pub_sign = data.get("public_sign_spki")
    if not pub_wrap or not pub_sign:
        return jsonify({"error": "missing public keys"}), 400

    # upsert: replace any existing public keys for this user+group
    user_group_pk = UserGroupKey.query.filter_by(user_id=current_user.id, group_id=group_id).first()
    if user_group_pk is None:
        user_group_pk = UserGroupKey(user_id=current_user.id, group_id=group_id,
                           public_wrap_spki=pub_wrap,
                           public_sign_spki=pub_sign)
        db.session.add(user_group_pk)
    else:
        user_group_pk.public_wrap_spki = pub_wrap
        user_group_pk.public_sign_spki = pub_sign
    db.session.commit()
    return jsonify({"status":"ok"})


@keys_bp.route("/<int:group_id>/members_public_keys", methods=["GET"])
@login_required
def members_public_keys(group_id):
    group = Group.query.get_or_404(group_id)
    # ensure caller is a member
    if current_user not in group.members:
        return jsonify({"error":"forbidden"}), 403

    # return list of members and their public wrap keys + sign keys
    rows = UserGroupKey.query.filter_by(group_id=group_id).all()
    # Only include users who uploaded public keys
    result = []
    for r in rows: #para cada usuario del grupo...
        result.append({
            "user_id": r.user_id,
            "username": r.user.username,
            "public_wrap_spki": r.public_wrap_spki,
            "public_sign_spki": r.public_sign_spki
        })
    return jsonify(result)
