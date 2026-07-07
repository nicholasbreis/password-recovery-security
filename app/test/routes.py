import random
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from app import db
from app.core.models import Usuario, PerguntaConfiavel, LogAuditoria
from app.core.services import OTPService, EmailService, AuditoriaService

test_bp = Blueprint("test", __name__)

MAX_TENTATIVAS = 3


# ─── FLUXO 1: Link por e-mail isolado ─────────────────────────────────────────

@test_bp.route("/link", methods=["GET", "POST"])
def link_iniciar():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        ip = request.remote_addr
        usuario = Usuario.query.filter_by(email=email).first()

        if not usuario or not usuario.eh_ativo:
            flash("Se este e-mail existir, você receberá o link em breve.", "info")
            return render_template("test/link_iniciar.html")

        token = OTPService.gerar_token_reset()
        expiracao = datetime.utcnow() + timedelta(minutes=30)

        # Salva token na sessão temporariamente
        session["link_token"] = token
        session["link_user_id"] = usuario.id
        session["link_expiracao"] = expiracao.isoformat()

        import os
        base = os.environ.get("BASE_URL", request.host_url.rstrip("/"))
        EmailService.enviar_link_reset(usuario.email, token, base, path="/test/link/reset")
        AuditoriaService.registrar("otp_enviado", user_id=usuario.id, tipo_fluxo="link_only", ip=ip)

        flash("Link enviado para o seu e-mail. Válido por 30 minutos.", "info")
        return redirect(url_for("test.link_aguardar"))

    return render_template("test/link_iniciar.html")


@test_bp.route("/link/aguardar")
def link_aguardar():
    return render_template("test/link_aguardar.html")


@test_bp.route("/link/reset", methods=["GET", "POST"])
def link_reset():
    token = request.args.get("token") or request.form.get("token")
    token_salvo = session.get("link_token")
    user_id = session.get("link_user_id")
    expiracao_str = session.get("link_expiracao")
    ip = request.remote_addr

    if not token or token != token_salvo or not user_id:
        flash("Link inválido.", "danger")
        return redirect(url_for("test.link_iniciar"))

    expiracao = datetime.fromisoformat(expiracao_str)
    if datetime.utcnow() > expiracao:
        flash("Link expirado. Inicie o processo novamente.", "danger")
        return redirect(url_for("test.link_iniciar"))

    if request.method == "POST":
        nova_senha = request.form.get("nova_senha", "")
        confirmar = request.form.get("confirmar_senha", "")

        if nova_senha != confirmar:
            flash("As senhas não coincidem.", "danger")
            return render_template("test/link_reset.html", token=token)

        if len(nova_senha) < 8:
            flash("A senha deve ter pelo menos 8 caracteres.", "danger")
            return render_template("test/link_reset.html", token=token)

        usuario = Usuario.query.get(user_id)
        usuario.definir_senha(nova_senha)
        usuario.eh_ativo = True
        usuario.resetar_tentativas()
        db.session.commit()

        session.pop("link_token", None)
        session.pop("link_user_id", None)
        session.pop("link_expiracao", None)

        AuditoriaService.registrar("reset_ok", user_id=user_id, tipo_fluxo="link_only", ip=ip)
        flash("Senha redefinida com sucesso!", "success")
        return redirect(url_for("auth.login"))

    return render_template("test/link_reset.html", token=token)


# ─── FLUXO 2: OTP isolado ─────────────────────────────────────────────────────

@test_bp.route("/otp", methods=["GET", "POST"])
def otp_iniciar():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        ip = request.remote_addr
        usuario = Usuario.query.filter_by(email=email).first()

        if not usuario or not usuario.eh_ativo:
            flash("Se este e-mail existir, você receberá o código em breve.", "info")
            return render_template("test/otp_iniciar.html")

        otp = OTPService.gerar()
        expiracao = OTPService.expiracao_otp(10)

        session["otp_code"] = otp
        session["otp_user_id"] = usuario.id
        session["otp_expiracao"] = expiracao.isoformat()
        session["otp_tentativas"] = 0

        EmailService.enviar_otp(usuario.email, otp)
        AuditoriaService.registrar("otp_enviado", user_id=usuario.id, tipo_fluxo="otp_only", ip=ip)

        flash("Código enviado para o seu e-mail. Válido por 10 minutos.", "info")
        return redirect(url_for("test.otp_verificar"))

    return render_template("test/otp_iniciar.html")


@test_bp.route("/otp/verificar", methods=["GET", "POST"])
def otp_verificar():
    user_id = session.get("otp_user_id")
    if not user_id:
        return redirect(url_for("test.otp_iniciar"))

    ip = request.remote_addr

    if request.method == "POST":
        codigo = "".join(request.form.getlist("digito")) or request.form.get("otp_code", "")
        expiracao = datetime.fromisoformat(session.get("otp_expiracao"))
        tentativas = session.get("otp_tentativas", 0)

        if datetime.utcnow() > expiracao:
            AuditoriaService.registrar("otp_expirado", user_id=user_id, tipo_fluxo="otp_only", ip=ip)
            flash("Código expirado. Inicie novamente.", "danger")
            return redirect(url_for("test.otp_iniciar"))

        if codigo != session.get("otp_code"):
            tentativas += 1
            session["otp_tentativas"] = tentativas
            restantes = MAX_TENTATIVAS - tentativas

            if tentativas >= MAX_TENTATIVAS:
                usuario = Usuario.query.get(user_id)
                usuario.bloquear_conta()
                db.session.commit()
                AuditoriaService.registrar("conta_bloqueada", user_id=user_id, tipo_fluxo="otp_only", ip=ip)
                session.pop("otp_code", None)
                session.pop("otp_user_id", None)
                flash("Conta bloqueada após 3 tentativas inválidas.", "danger")
                return redirect(url_for("auth.login"))

            AuditoriaService.registrar("otp_fail", user_id=user_id, tipo_fluxo="otp_only", ip=ip)
            flash(f"Código incorreto. {restantes} tentativa(s) restante(s).", "danger")
            return render_template("test/otp_verificar.html")

        # OTP correto — gera token de reset
        token = OTPService.gerar_token_reset()
        expiracao_reset = OTPService.expiracao_token(5)
        session["otp_reset_token"] = token
        session["otp_reset_expiracao"] = expiracao_reset.isoformat()
        AuditoriaService.registrar("otp_ok", user_id=user_id, tipo_fluxo="otp_only", ip=ip)

        import os
        base = os.environ.get("BASE_URL", request.host_url.rstrip("/"))
        usuario = Usuario.query.get(user_id)
        EmailService.enviar_link_reset(usuario.email, token, base + "/test/otp/reset?token=")
        return redirect(url_for("test.otp_reset", token=token))

    return render_template("test/otp_verificar.html")


@test_bp.route("/otp/reset", methods=["GET", "POST"])
def otp_reset():
    token = request.args.get("token") or request.form.get("token")
    user_id = session.get("otp_user_id")
    ip = request.remote_addr

    if not token or token != session.get("otp_reset_token") or not user_id:
        flash("Link inválido.", "danger")
        return redirect(url_for("test.otp_iniciar"))

    expiracao = datetime.fromisoformat(session.get("otp_reset_expiracao"))
    if datetime.utcnow() > expiracao:
        flash("Link expirado.", "danger")
        return redirect(url_for("test.otp_iniciar"))

    if request.method == "POST":
        nova_senha = request.form.get("nova_senha", "")
        confirmar = request.form.get("confirmar_senha", "")

        if nova_senha != confirmar:
            flash("As senhas não coincidem.", "danger")
            return render_template("test/reset_generico.html", token=token, fluxo="otp_only")

        usuario = Usuario.query.get(user_id)
        usuario.definir_senha(nova_senha)
        usuario.eh_ativo = True
        usuario.resetar_tentativas()
        db.session.commit()

        for key in ["otp_code", "otp_user_id", "otp_expiracao", "otp_tentativas", "otp_reset_token", "otp_reset_expiracao"]:
            session.pop(key, None)

        AuditoriaService.registrar("reset_ok", user_id=user_id, tipo_fluxo="otp_only", ip=ip)
        flash("Senha redefinida com sucesso!", "success")
        return redirect(url_for("auth.login"))

    return render_template("test/reset_generico.html", token=token, fluxo="otp_only")


# ─── FLUXO 3: Pergunta isolada ────────────────────────────────────────────────

@test_bp.route("/pergunta", methods=["GET", "POST"])
def pergunta_iniciar():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        ip = request.remote_addr
        usuario = Usuario.query.filter_by(email=email).first()

        if not usuario or not usuario.eh_ativo:
            flash("Se este e-mail existir, você poderá responder à pergunta.", "info")
            return render_template("test/pergunta_iniciar.html")

        perguntas = PerguntaConfiavel.query.filter_by(user_id=usuario.id, validado=True).all()
        if not perguntas:
            flash("Este usuário não possui perguntas cadastradas.", "danger")
            return render_template("test/pergunta_iniciar.html")

        pergunta = random.choice(perguntas)
        session["perg_user_id"] = usuario.id
        session["perg_id"] = pergunta.id
        session["perg_tentativas"] = 0

        AuditoriaService.registrar("otp_enviado", user_id=usuario.id, tipo_fluxo="pergunta_only", ip=ip)
        return redirect(url_for("test.pergunta_verificar"))

    return render_template("test/pergunta_iniciar.html")


@test_bp.route("/pergunta/verificar", methods=["GET", "POST"])
def pergunta_verificar():
    user_id = session.get("perg_user_id")
    pergunta_id = session.get("perg_id")

    if not user_id or not pergunta_id:
        return redirect(url_for("test.pergunta_iniciar"))

    pergunta_obj = PerguntaConfiavel.query.get(pergunta_id)
    ip = request.remote_addr

    if request.method == "POST":
        resposta = request.form.get("resposta", "").strip()
        tentativas = session.get("perg_tentativas", 0)

        if not pergunta_obj.verificar_resposta(resposta):
            tentativas += 1
            session["perg_tentativas"] = tentativas
            restantes = MAX_TENTATIVAS - tentativas

            if tentativas >= MAX_TENTATIVAS:
                usuario = Usuario.query.get(user_id)
                usuario.bloquear_conta()
                db.session.commit()
                AuditoriaService.registrar("conta_bloqueada", user_id=user_id, tipo_fluxo="pergunta_only", ip=ip)
                for key in ["perg_user_id", "perg_id", "perg_tentativas"]:
                    session.pop(key, None)
                flash("Conta bloqueada após 3 tentativas inválidas.", "danger")
                return redirect(url_for("auth.login"))

            AuditoriaService.registrar("pergunta_fail", user_id=user_id, tipo_fluxo="pergunta_only", ip=ip)
            flash(f"Resposta incorreta. {restantes} tentativa(s) restante(s).", "danger")
            return render_template("test/pergunta_verificar.html", pergunta=pergunta_obj)

        # Resposta correta
        token = OTPService.gerar_token_reset()
        expiracao = OTPService.expiracao_token(5)
        session["perg_reset_token"] = token
        session["perg_reset_expiracao"] = expiracao.isoformat()
        AuditoriaService.registrar("pergunta_ok", user_id=user_id, tipo_fluxo="pergunta_only", ip=ip)
        return redirect(url_for("test.pergunta_reset", token=token))

    return render_template("test/pergunta_verificar.html", pergunta=pergunta_obj)


@test_bp.route("/pergunta/reset", methods=["GET", "POST"])
def pergunta_reset():
    token = request.args.get("token") or request.form.get("token")
    user_id = session.get("perg_user_id")
    ip = request.remote_addr

    if not token or token != session.get("perg_reset_token") or not user_id:
        flash("Link inválido.", "danger")
        return redirect(url_for("test.pergunta_iniciar"))

    expiracao = datetime.fromisoformat(session.get("perg_reset_expiracao"))
    if datetime.utcnow() > expiracao:
        flash("Link expirado.", "danger")
        return redirect(url_for("test.pergunta_iniciar"))

    if request.method == "POST":
        nova_senha = request.form.get("nova_senha", "")
        confirmar = request.form.get("confirmar_senha", "")

        if nova_senha != confirmar:
            flash("As senhas não coincidem.", "danger")
            return render_template("test/reset_generico.html", token=token, fluxo="pergunta_only")

        usuario = Usuario.query.get(user_id)
        usuario.definir_senha(nova_senha)
        usuario.eh_ativo = True
        usuario.resetar_tentativas()
        db.session.commit()

        for key in ["perg_user_id", "perg_id", "perg_tentativas", "perg_reset_token", "perg_reset_expiracao"]:
            session.pop(key, None)

        AuditoriaService.registrar("reset_ok", user_id=user_id, tipo_fluxo="pergunta_only", ip=ip)
        flash("Senha redefinida com sucesso!", "success")
        return redirect(url_for("auth.login"))

    return render_template("test/reset_generico.html", token=token, fluxo="pergunta_only")


# ─── Painel de seleção de fluxo ───────────────────────────────────────────────

@test_bp.route("/")
def painel():
    return render_template("test/painel.html")
