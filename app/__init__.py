from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()


def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = "dev-secret-key-troque-em-producao"
    app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:root@db:3306/recuperacao_db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAIL_SERVER"] = "mail"
    app.config["MAIL_PORT"] = 1025
    app.config["MAIL_USE_TLS"] = False
    app.config["MAIL_DEFAULT_SENDER"] = "sistema@recuperacao.local"

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Faça login para acessar esta página."

    from app.auth.routes import auth_bp
    from app.recovery.routes import recovery_bp
    from app.admin.routes import admin_bp
    from app.analista.routes import analista_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(recovery_bp, url_prefix="/recovery")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(analista_bp, url_prefix="/analista")

    return app