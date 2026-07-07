import os
import random
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from app import db
from app.core.models import Usuario, Recuperacao, PerguntaConfiavel, LogAuditoria
from app.core.services import OTPService, EmailService, AuditoriaService

recovery_bp = Blueprint("recovery", __name__)

MAX_TENTATIVAS = 3
FLUXO = "proposto"


@recovery_bp.route("/", methods=["GET", "POST"])
def iniciar():
    """Etapa 0 — usuário informa o e-mail."""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        ip = request.remote_addr
        usuario = Usuario.query.filter_by(email=email).first()

        # Sempre retorna a mesma mensagem para evitar enumeração de usuários
        if not usuario or not usuario.eh_ativo:
            flash("Se este e-mail existir, você receberá o código em breve.", "info")
            return render_template("recovery/iniciar.html")

        perguntas = PerguntaConfiavel.query.filter_by(user_id=usuario.id, validado=True).all()
        if not perguntas:
            flash("Este usuário não possui perguntas confiáveis cadastradas.", "danger")
            return render_template("recovery/iniciar.html")

        # Invalida sessões anteriores
        Recuperacao.query.filter_by(user_id=usuario.id).delete()

        otp = OTPService.gerar()
        pergunta = random.choice(perguntas)

        sessao = Recuperacao(
            user_id=usuario.id,
            otp_code=otp,
            otp_expira_em=OTPService.expiracao_otp(10),
            pergunta_id=pergunta.id,
            estagio="otp_pendente"
        )
        db.session.add(sessao)
        db.session.commit()

        EmailService.enviar_otp(usuario.email, otp)
        AuditoriaService.registrar("otp_enviado", user_id=usuario.id, tipo_fluxo=FLUXO, ip=ip)

        session["recovery_user_id"] = usuario.id
        flash("Código enviado para o seu e-mail.", "info")
        return redirect(url_for("recovery.otp"))

    return render_template("recovery/iniciar.html")


@recovery_bp.route("/otp", methods=["GET", "POST"])
def otp():
    """Etapa 1 — validação do OTP."""
    user_id = session.get("recovery_user_id")
    if not user_id:
        return redirect(url_for("recovery.iniciar"))

    sessao = Recuperacao.query.filter_by(user_id=user_id, estagio="otp_pendente").first()
    if not sessao:
        return redirect(url_for("recovery.iniciar"))

    ip = request.remote_addr

    if request.method == "POST":
        codigo = "".join(request.form.getlist("digito")) or request.form.get("otp_code", "")

        if sessao.otp_expirado():
            AuditoriaService.registrar("otp_expirado", user_id=user_id, tipo_fluxo=FLUXO, ip=ip)
            flash("Código expirado. Inicie o processo novamente.", "danger")
            return redirect(url_for("recovery.iniciar"))

        if codigo != sessao.otp_code:
            sessao.incrementar_tentativas()
            restantes = MAX_TENTATIVAS - sessao.tentativas

            if sessao.tentativas >= MAX_TENTATIVAS:
                sessao.avancar_estagio("bloqueado")
                usuario = Usuario.query.get(user_id)
                usuario.bloquear_conta()
                db.session.commit()
                AuditoriaService.registrar("conta_bloqueada", user_id=user_id, tipo_fluxo=FLUXO, ip=ip)
                session.pop("recovery_user_id", None)
                flash("Conta bloqueada após 3 tentativas inválidas.", "danger")
                return redirect(url_for("auth.login"))

            db.session.commit()
            AuditoriaService.registrar("otp_fail", user_id=user_id, tipo_fluxo=FLUXO, ip=ip)
            flash(f"Código incorreto. {restantes} tentativa(s) restante(s).", "danger")
            return render_template("recovery/otp.html")

        # OTP correto — avança para etapa 2
        sessao.avancar_estagio("pergunta_pendente")
        db.session.commit()
        AuditoriaService.registrar("otp_ok", user_id=user_id, tipo_fluxo=FLUXO, ip=ip)
        return redirect(url_for("recovery.pergunta"))

    return render_template("recovery/otp.html")


@recovery_bp.route("/pergunta", methods=["GET", "POST"])
def pergunta():
    """Etapa 2 — validação da pergunta confiável."""
    user_id = session.get("recovery_user_id")
    if not user_id:
        return redirect(url_for("recovery.iniciar"))

    sessao = Recuperacao.query.filter_by(user_id=user_id, estagio="pergunta_pendente").first()
    if not sessao:
        return redirect(url_for("recovery.iniciar"))

    pergunta_obj = PerguntaConfiavel.query.get(sessao.pergunta_id)
    ip = request.remote_addr

    if request.method == "POST":
        resposta = request.form.get("resposta", "").strip()

        if not pergunta_obj.verificar_resposta(resposta):
            sessao.incrementar_tentativas()
            restantes = MAX_TENTATIVAS - sessao.tentativas

            if sessao.tentativas >= MAX_TENTATIVAS:
                sessao.avancar_estagio("bloqueado")
                usuario = Usuario.query.get(user_id)
                usuario.bloquear_conta()
                db.session.commit()
                AuditoriaService.registrar("conta_bloqueada", user_id=user_id, tipo_fluxo=FLUXO, ip=ip)
                session.pop("recovery_user_id", None)
                flash("Conta bloqueada após 3 tentativas inválidas.", "danger")
                return redirect(url_for("auth.login"))

            db.session.commit()
            AuditoriaService.registrar("pergunta_fail", user_id=user_id, tipo_fluxo=FLUXO, ip=ip)
            flash(f"Resposta incorreta. {restantes} tentativa(s) restante(s).", "danger")
            return render_template("recovery/pergunta.html", pergunta=pergunta_obj)

        # Resposta correta — gera token de redefinição
        token = OTPService.gerar_token_reset()
        sessao.reset_token = token
        sessao.expiracao_em = OTPService.expiracao_token(5)
        sessao.avancar_estagio("concluido")
        db.session.commit()

        usuario = Usuario.query.get(user_id)
        base = os.environ.get("BASE_URL", request.host_url.rstrip("/"))
        EmailService.enviar_link_reset(usuario.email, token, base)
        AuditoriaService.registrar("pergunta_ok", user_id=user_id, tipo_fluxo=FLUXO, ip=ip)
        flash("Identidade confirmada! Verifique seu e-mail para o link de redefinição.", "success")
        return redirect(url_for("recovery.aguardar_reset"))

    return render_template("recovery/pergunta.html", pergunta=pergunta_obj)


@recovery_bp.route("/aguardar")
def aguardar_reset():
    return render_template("recovery/aguardar.html")


@recovery_bp.route("/reset", methods=["GET", "POST"])
def reset():
    """Etapa 3 — redefinição de senha com token de alta entropia."""
    token = request.args.get("token") or request.form.get("token")
    sessao = Recuperacao.query.filter_by(reset_token=token, estagio="concluido").first()

    if not sessao or sessao.token_expirado():
        flash("Link inválido ou expirado.", "danger")
        return redirect(url_for("recovery.iniciar"))

    ip = request.remote_addr

    if request.method == "POST":
        nova_senha = request.form.get("nova_senha", "")
        confirmar = request.form.get("confirmar_senha", "")

        if nova_senha != confirmar:
            flash("As senhas não coincidem.", "danger")
            return render_template("recovery/reset.html", token=token)

        if len(nova_senha) < 8:
            flash("A senha deve ter pelo menos 8 caracteres.", "danger")
            return render_template("recovery/reset.html", token=token)

        usuario = Usuario.query.get(sessao.user_id)
        usuario.definir_senha(nova_senha)
        usuario.eh_ativo = True
        usuario.resetar_tentativas()

        # Invalida o token após uso
        sessao.reset_token = None
        sessao.estagio = "bloqueado"
        db.session.commit()

        session.pop("recovery_user_id", None)
        AuditoriaService.registrar("reset_ok", user_id=usuario.id, tipo_fluxo=FLUXO, ip=ip)
        flash("Senha redefinida com sucesso! Faça login.", "success")
        return redirect(url_for("auth.login"))

    return render_template("recovery/reset.html", token=token)