# app/admin/routes.py
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from app import db
from app.core.models import Usuario, LogAuditoria
from app.core.services import AuditoriaService

admin_bp = Blueprint("admin", __name__)


def requer_admin(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.perfil != "admin":
            flash("Acesso restrito a administradores.", "danger")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


@admin_bp.route("/usuarios")
@login_required
@requer_admin
def usuarios():
    lista = Usuario.query.order_by(Usuario.criado_em.desc()).all()
    return render_template("admin/usuarios.html", usuarios=lista)


@admin_bp.route("/usuarios/novo", methods=["GET", "POST"])
@login_required
@requer_admin
def novo_usuario():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        perfil = request.form.get("perfil", "usuario")
        senha = request.form.get("senha", "")

        if Usuario.query.filter_by(email=email).first():
            flash("E-mail já cadastrado.", "danger")
            return render_template("admin/form_usuario.html")

        u = Usuario(nome=nome, email=email, perfil=perfil)
        u.definir_senha(senha)
        db.session.add(u)
        db.session.commit()
        flash("Usuário criado com sucesso.", "success")
        return redirect(url_for("admin.usuarios"))

    return render_template("admin/form_usuario.html")


@admin_bp.route("/usuarios/<int:uid>/bloquear", methods=["POST"])
@login_required
@requer_admin
def bloquear(uid):
    u = Usuario.query.get_or_404(uid)
    u.bloquear_conta()
    db.session.commit()
    flash(f"Usuário {u.nome} bloqueado.", "warning")
    return redirect(url_for("admin.usuarios"))


@admin_bp.route("/usuarios/<int:uid>/desbloquear", methods=["POST"])
@login_required
@requer_admin
def desbloquear(uid):
    u = Usuario.query.get_or_404(uid)
    u.eh_ativo = True
    u.tentativas = 0
    db.session.commit()
    flash(f"Usuário {u.nome} desbloqueado.", "success")
    return redirect(url_for("admin.usuarios"))