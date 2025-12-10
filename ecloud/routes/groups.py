from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user

from ecloud.extensions import db
from ecloud.models.user import User
from ecloud.models.group import Group, group_members
from ecloud.forms.group_form import CreateGroupForm
from sqlalchemy import insert
groups_bp = Blueprint("groups", __name__, url_prefix="/groups")


# --------------------------
# CREATE NEW GROUP
# --------------------------
@groups_bp.route("/create", methods=["GET", "POST"])
@login_required
def create_group():
    form = CreateGroupForm()

    if form.validate_on_submit():
        groupname = form.groupname.data.strip()
        selected_user_ids = request.form.getlist("users")
        # Check if already exists
        existing = Group.query.filter_by(groupname=groupname).first()
        if existing:
            flash("A group with this name already exists.", "danger")
            return redirect(url_for("groups.create_group"))

        # Create group
        new_group = Group(groupname=groupname, owner_id=current_user.id)
        db.session.add(new_group)
        db.session.commit()

        for user_id in selected_user_ids:
            db.session.execute(
                insert(group_members).values(group_id=new_group.id, user_id=int(user_id))
            )
        # Add owner as first member
        new_group.members.append(current_user)
        db.session.commit()

        flash("Group created successfully!", "success")
        return redirect(url_for("dashboard.dashboard"))
    all_users = User.query.filter(User.id != current_user.id).all() 
    return render_template("create_group.html", form=form, users=all_users)
