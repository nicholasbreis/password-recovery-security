import secrets
import re
from datetime import datetime, timedelta
from flask_mail import Message
from app import mail


# ─── OTP Service ───────────────────────────────────────────
class OTPService:
    """
    Gera códigos OTP de 6 dígitos numéricos para verificação na Etapa 1.
    Entropia real: ~20 bits (10^6 possibilidades).
    Nota: o link final de redefinição usa secrets.token_hex(32) — 256 bits de entropia.
    """

    @staticmethod
    def gerar() -> str:
        """Retorna string de 6 dígitos com padding de zeros."""
        return str(secrets.randbelow(1_000_000)).zfill(6)

    @staticmethod
    def expiracao_otp(minutos: int = 10) -> datetime:
        return datetime.utcnow() + timedelta(minutes=minutos)

    @staticmethod
    def gerar_token_reset() -> str:
        """Token de alta entropia (256 bits) para o link final de redefinição."""
        return secrets.token_hex(32)

    @staticmethod
    def expiracao_token(minutos: int = 5) -> datetime:
        return datetime.utcnow() + timedelta(minutes=minutos)


# ─── Question Validator Service ────────────────────────────
class ValidadorPerguntaService:
    """
    Valida a qualidade das respostas para perguntas confiáveis.
    Critérios conforme RF13 e RF14.
    """

    REGEX_DATA = re.compile(r"^\d{4}$|^\d{2}/\d{2}/\d{4}$")
    REGEX_APENAS_NUMEROS = re.compile(r"^\d+$")

    @classmethod
    def validar(cls, resposta: str, nome_usuario: str, email_usuario: str) -> tuple[bool, str]:
        """
        Retorna (valido: bool, motivo: str).
        """
        r = resposta.strip()

        if not r:
            return False, "A resposta não pode ser vazia."

        palavras = r.split()
        if len(palavras) < 4:
            return False, f"A resposta deve ter no mínimo 4 palavras (atual: {len(palavras)})."

        if cls.REGEX_APENAS_NUMEROS.match(r):
            return False, "A resposta não pode conter apenas números."

        if cls.REGEX_DATA.match(r):
            return False, "A resposta não pode ser uma data isolada."

        if r.lower() == nome_usuario.strip().lower():
            return False, "A resposta não pode ser idêntica ao seu nome."

        if r.lower() == email_usuario.strip().lower():
            return False, "A resposta não pode ser idêntica ao seu e-mail."

        return True, "ok"


# ─── Email Service ─────────────────────────────────────────
class EmailService:

    @staticmethod
    def enviar_otp(destinatario: str, codigo: str):
        msg = Message(
            subject="Código de verificação — Recuperação de senha",
            recipients=[destinatario],
            body=(
                f"Seu código de verificação é: {codigo}\n\n"
                f"Este código é válido por 10 minutos e deve ser usado apenas uma vez.\n"
                f"Se você não solicitou a recuperação de senha, ignore este e-mail."
            )
        )
        mail.send(msg)

    @staticmethod
    def enviar_link_reset(destinatario: str, token: str, base_url: str):
        link = f"{base_url}/recovery/reset?token={token}"
        msg = Message(
            subject="Link de redefinição de senha",
            recipients=[destinatario],
            body=(
                f"Clique no link abaixo para redefinir sua senha:\n\n{link}\n\n"
                f"Este link é válido por 5 minutos e só pode ser usado uma vez.\n"
                f"Se você não solicitou a redefinição, ignore este e-mail."
            )
        )
        mail.send(msg)


# ─── Audit Service ─────────────────────────────────────────
class AuditoriaService:

    EVENTOS = {
        "login_ok", "login_fail", "login_bloqueado",
        "otp_enviado", "otp_ok", "otp_fail", "otp_expirado",
        "pergunta_ok", "pergunta_fail",
        "reset_ok", "conta_bloqueada",
        "cadastro_ok", "pergunta_cadastrada",
    }

    @staticmethod
    def registrar(tipo_evento: str, user_id=None, tipo_fluxo=None, ip=None):
        from app.core.models import LogAuditoria
        LogAuditoria.registrar(
            tipo_evento=tipo_evento,
            user_id=user_id,
            tipo_fluxo=tipo_fluxo,
            ip=ip
        )