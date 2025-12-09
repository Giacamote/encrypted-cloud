from flask import Flask
from dotenv import load_dotenv
import os

from ecloud.extensions import db, bcrypt, login_manager

def create_app():
    load_dotenv()

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
    app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    # ---------------------------
    #   🟢 REGISTER USER LOADER
    # ---------------------------
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register blueprints
    from ecloud.routes.auth import auth_bp
    from ecloud.routes.dashboard import dashboard_bp
    from ecloud.routes.upload import upload_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(upload_bp)

    with app.app_context():
        from ecloud.models import User, File
        db.create_all()

    return app
