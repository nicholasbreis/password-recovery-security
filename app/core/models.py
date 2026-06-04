from datetime import datetime
from flask_login import UserMixin
from app import db, login_manager
import bcrypt


class Usuario(UserMixin, db.Model):
    __tablename__ = "usuario"

    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    senha_hash = db.Column(db.String(255), nullable=False)
    perfil = db.Column(db.Enum("admin", "usuario", "analista"), nullable=False, default="usuario")
    eh_ativo = db.Column(db.Boolean, nullable=False, default=True)
    tentativas = db.Column(db.Integer, nullable=False, default=0)
    criado_em = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    perguntas = db.relationship("PerguntaConfiavel", backref="usuario", lazy=True, cascade="all, delete")
    recuperacoes = db.relationship("Recuperacao", backref="usuario", lazy=True, cascade="all, delete")
    logs = db.relationship("LogAuditoria", backref="usuario", lazy=True)

    def verificar_senha(self, senha: str) -> bool:
        return bcrypt.checkpw(senha.encode(), self.senha_hash.encode())

    def definir_senha(self, senha: str):
        self.senha_hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt(rounds=12)).decode()

    def bloquear_conta(self):
        self.eh_ativo = False
        self.tentativas = 0

    def incrementar_tentativas(self):
        self.tentativas += 1

    def resetar_tentativas(self):
        self.tentativas = 0

    @property
    def is_active(self):
        return self.eh_ativo


class PerguntaConfiavel(db.Model):
    __tablename__ = "pergunta_confiavel"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=False)
    texto_pergunta = db.Column(db.String(300), nullable=False)
    resposta_hash = db.Column(db.String(255), nullable=False)
    validado = db.Column(db.Boolean, nullable=False, default=False)
    criado_em = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def definir_resposta(self, resposta: str):
        self.resposta_hash = bcrypt.hashpw(
            resposta.strip().lower().encode(), bcrypt.gensalt(rounds=12)
        ).decode()

    def verificar_resposta(self, resposta: str) -> bool:
        return bcrypt.checkpw(resposta.strip().lower().encode(), self.resposta_hash.encode())


class Recuperacao(db.Model):
    __tablename__ = "recuperacao"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=False)
    otp_code = db.Column(db.String(6))
    otp_expira_em = db.Column(db.DateTime)
    pergunta_id = db.Column(db.Integer, db.ForeignKey("pergunta_confiavel.id"))
    reset_token = db.Column(db.String(255))
    expiracao_em = db.Column(db.DateTime)
    tentativas = db.Column(db.Integer, nullable=False, default=0)
    estagio = db.Column(
        db.Enum("otp_pendente", "pergunta_pendente", "concluido", "bloqueado"),
        nullable=False, default="otp_pendente"
    )
    criado_em = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    pergunta = db.relationship("PerguntaConfiavel", lazy=True)

    def otp_expirado(self) -> bool:
        return datetime.utcnow() > self.otp_expira_em if self.otp_expira_em else True

    def token_expirado(self) -> bool:
        return datetime.utcnow() > self.expiracao_em if self.expiracao_em else True

    def incrementar_tentativas(self):
        self.tentativas += 1

    def avancar_estagio(self, novo_estagio: str):
        self.estagio = novo_estagio
        self.tentativas = 0


class LogAuditoria(db.Model):
    __tablename__ = "log_auditoria"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("usuario.id"), nullable=True)
    tipo_fluxo = db.Column(db.Enum("proposto", "link_only", "otp_only", "pergunta_only"), nullable=True)
    tipo_evento = db.Column(db.String(50), nullable=False)
    endereco_ip = db.Column(db.String(45))
    criado_em = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    @staticmethod
    def registrar(tipo_evento: str, user_id=None, tipo_fluxo=None, ip=None):
        log = LogAuditoria(
            user_id=user_id,
            tipo_fluxo=tipo_fluxo,
            tipo_evento=tipo_evento,
            endereco_ip=ip
        )
        db.session.add(log)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return Usuario.query.get(int(user_id))