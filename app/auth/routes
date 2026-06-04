from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.core.models import Usuario, LogAuditoria
from app.core.services import AuditoriaService

auth_bp = Blueprint("auth", __name__)

MAX_TENTATIVAS = 3


@auth_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for(f"auth.dashboard_{current_user.perfil}"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("auth.index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        ip = request.remote_addr

        usuario = Usuario.query.filter_by(email=email).first()

        if not usuario:
            flash("Credenciais inválidas.", "danger")
            AuditoriaService.registrar("login_fail", ip=ip)
            return render_template("auth/login.html")

        if not usuario.eh_ativo:
            flash("Conta bloqueada. Entre em contato com o administrador.", "danger")
            AuditoriaService.registrar("login_bloqueado", user_id=usuario.id, ip=ip)
            return render_template("auth/login.html")

        if not usuario.verificar_senha(senha):
            usuario.incrementar_tentativas()
            restantes = MAX_TENTATIVAS - usuario.tentativas

            if usuario.tentativas >= MAX_TENTATIVAS:
                usuario.bloquear_conta()
                db.session.commit()
                AuditoriaService.registrar("conta_bloqueada", user_id=usuario.id, ip=ip)
                flash("Conta bloqueada após 3 tentativas falhas.", "danger")
            else:
                db.session.commit()
                AuditoriaService.registrar("login_fail", user_id=usuario.id, ip=ip)
                flash(f"Credenciais inválidas. {restantes} tentativa(s) restante(s).", "danger")
            return render_template("auth/login.html")

        usuario.resetar_tentativas()
        db.session.commit()
        login_user(usuario)
        AuditoriaService.registrar("login_ok", user_id=usuario.id, ip=ip)
        return redirect(url_for("auth.index"))

    return render_template("auth/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        confirmar = request.form.get("confirmar_senha", "")

        if senha != confirmar:
            flash("As senhas não coincidem.", "danger")
            return render_template("auth/register.html")

        if Usuario.query.filter_by(email=email).first():
            flash("Este e-mail já está cadastrado.", "danger")
            return render_template("auth/register.html")

        usuario = Usuario(nome=nome, email=email, perfil="usuario")
        usuario.definir_senha(senha)
        db.session.add(usuario)
        db.session.commit()
        AuditoriaService.registrar("cadastro_ok", user_id=usuario.id, ip=request.remote_addr)
        flash("Conta criada! Cadastre pelo menos 3 perguntas confiáveis antes de continuar.", "success")
        login_user(usuario)
        return redirect(url_for("auth.perguntas"))

    return render_template("auth/register.html")


@auth_bp.route("/perguntas", methods=["GET", "POST"])
@login_required
def perguntas():
    from app.core.models import PerguntaConfiavel
    from app.core.services import ValidadorPerguntaService

    if request.method == "POST":
        textos = request.form.getlist("texto_pergunta")
        respostas = request.form.getlist("resposta")
        erros = []

        for i, (texto, resposta) in enumerate(zip(textos, respostas), 1):
            if not texto.strip() or not resposta.strip():
                continue
            valido, motivo = ValidadorPerguntaService.validar(
                resposta, current_user.nome, current_user.email
            )
            if not valido:
                erros.append(f"Pergunta {i}: {motivo}")

        perguntas_existentes = PerguntaConfiavel.query.filter_by(user_id=current_user.id).count()
        novas_validas = sum(
            1 for t, r in zip(textos, respostas)
            if t.strip() and r.strip() and ValidadorPerguntaService.validar(r, current_user.nome, current_user.email)[0]
        )

        if erros:
            for e in erros:
                flash(e, "danger")
            return render_template("auth/perguntas.html")

        if perguntas_existentes + novas_validas < 3:
            flash("Cadastre ao menos 3 perguntas confiáveis válidas.", "danger")
            return render_template("auth/perguntas.html")

        for texto, resposta in zip(textos, respostas):
            if not texto.strip() or not resposta.strip():
                continue
            valido, _ = ValidadorPerguntaService.validar(resposta, current_user.nome, current_user.email)
            if valido:
                p = PerguntaConfiavel(
                    user_id=current_user.id,
                    texto_pergunta=texto.strip(),
                    validado=True
                )
                p.definir_resposta(resposta)
                db.session.add(p)
                AuditoriaService.registrar("pergunta_cadastrada", user_id=current_user.id)

        db.session.commit()
        flash("Perguntas salvas com sucesso!", "success")
        return redirect(url_for("auth.index"))

    perguntas_atuais = PerguntaConfiavel.query.filter_by(user_id=current_user.id, validado=True).all()
    return render_template("auth/perguntas.html", perguntas_atuais=perguntas_atuais)


@auth_bp.route("/dashboard/usuario")
@login_required
def dashboard_usuario():
    return render_template("auth/dashboard_usuario.html")


@auth_bp.route("/dashboard/admin")
@login_required
def dashboard_admin():
    if current_user.perfil != "admin":
        return redirect(url_for("auth.index"))
    return redirect(url_for("admin.usuarios"))


@auth_bp.route("/dashboard/analista")
@login_required
def dashboard_analista():
    if current_user.perfil != "analista":
        return redirect(url_for("auth.index"))
    return redirect(url_for("analista.logs"))