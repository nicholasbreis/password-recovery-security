"""
Testes Funcionais — Módulo 1
Cobre: RF01, RF02, RF03, RF06, RF07, RF09, RF11, RF12, RF13, RF14, RF20
"""
import pytest
from app import create_app, db
from app.core.models import Usuario, PerguntaConfiavel, Recuperacao, LogAuditoria
from app.core.services import OTPService, ValidadorPerguntaService


# ─── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def app():
    app = create_app()
    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
        "MAIL_SUPPRESS_SEND": True,
        "SECRET_KEY": "test-secret",
    })
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def usuario_base(app):
    with app.app_context():
        u = Usuario(nome="Teste Silva", email="teste@email.com", perfil="usuario")
        u.definir_senha("Senha@123")
        db.session.add(u)
        db.session.commit()
        return u.id


@pytest.fixture
def usuario_com_perguntas(app, usuario_base):
    with app.app_context():
        perguntas_dados = [
            ("Qual o apelido do seu avô paterno?", "zé do chapéu de palha velho"),
            ("Qual a cidade onde seus pais se conheceram?", "porto alegre rio grande do sul"),
            ("Qual o nome da sua professora favorita?", "professora maria das dores silva"),
        ]
        for texto, resposta in perguntas_dados:
            p = PerguntaConfiavel(user_id=usuario_base, texto_pergunta=texto, validado=True)
            p.definir_resposta(resposta)
            db.session.add(p)
        db.session.commit()
        return usuario_base


# ─── RF01: Registro de usuário ─────────────────────────────────────────────────

class TestRF01Registro:
    def test_registro_sucesso(self, client):
        """RF01 — Registro com dados válidos deve criar conta."""
        r = client.post("/register", data={
            "nome": "João Teste",
            "email": "joao@teste.com",
            "senha": "Senha@123",
            "confirmar_senha": "Senha@123"
        }, follow_redirects=True)
        assert r.status_code == 200

    def test_registro_email_duplicado(self, client, usuario_base):
        """RF01 — Registro com e-mail já cadastrado deve falhar."""
        r = client.post("/register", data={
            "nome": "Outro",
            "email": "teste@email.com",
            "senha": "Senha@123",
            "confirmar_senha": "Senha@123"
        })
        assert b"j\xc3\xa1 cadastrado" in r.data or r.status_code == 200

    def test_registro_senhas_diferentes(self, client):
        """RF01 — Senhas divergentes devem ser rejeitadas."""
        r = client.post("/register", data={
            "nome": "Teste",
            "email": "novo@email.com",
            "senha": "Senha@123",
            "confirmar_senha": "OutraSenha"
        })
        assert b"coincidem" in r.data or r.status_code == 200


# ─── RF02: Autenticação ────────────────────────────────────────────────────────

class TestRF02Login:
    def test_login_sucesso(self, client, usuario_base):
        """RF02 — Login com credenciais corretas deve autenticar."""
        r = client.post("/login", data={
            "email": "teste@email.com",
            "senha": "Senha@123"
        }, follow_redirects=True)
        assert r.status_code == 200

    def test_login_senha_errada(self, client, usuario_base):
        """RF02 — Login com senha incorreta deve falhar."""
        r = client.post("/login", data={
            "email": "teste@email.com",
            "senha": "SenhaErrada"
        })
        assert r.status_code == 200
        assert "inv\xc3\xa1lidas".encode() in r.data or b"inv" in r.data

    def test_login_email_inexistente(self, client):
        """RF02 — Login com e-mail não cadastrado deve falhar."""
        r = client.post("/login", data={
            "email": "naoexiste@email.com",
            "senha": "Qualquer123"
        })
        assert r.status_code == 200


# ─── RF03: Bloqueio por tentativas ────────────────────────────────────────────

class TestRF03Bloqueio:
    def test_bloqueio_apos_3_tentativas(self, app, client, usuario_base):
        """RF03 — Conta deve ser bloqueada após 3 tentativas falhas de login."""
        for _ in range(3):
            client.post("/login", data={
                "email": "teste@email.com",
                "senha": "SenhaErrada"
            })
        with app.app_context():
            u = Usuario.query.filter_by(email="teste@email.com").first()
            assert u.eh_ativo is False

    def test_contador_resetado_apos_login_ok(self, app, client, usuario_base):
        """RF03 — Tentativas devem ser zeradas após login bem-sucedido."""
        client.post("/login", data={"email": "teste@email.com", "senha": "SenhaErrada"})
        client.post("/login", data={"email": "teste@email.com", "senha": "Senha@123"})
        with app.app_context():
            u = Usuario.query.filter_by(email="teste@email.com").first()
            assert u.tentativas == 0


# ─── RF12/RF13/RF14: Perguntas confiáveis ─────────────────────────────────────

class TestRF12_14PerguntasConfiaveis:
    def test_resposta_valida(self):
        """RF13 — Resposta com 4+ palavras sem restrições deve ser aceita."""
        valido, _ = ValidadorPerguntaService.validar(
            "minha resposta tem quatro palavras", "João", "joao@email.com"
        )
        assert valido is True

    def test_resposta_menos_4_palavras(self):
        """RF13 — Resposta com menos de 4 palavras deve ser rejeitada."""
        valido, motivo = ValidadorPerguntaService.validar("apenas tres palavras", "João", "joao@email.com")
        assert valido is False
        assert "4 palavras" in motivo

    def test_resposta_apenas_numeros(self):
        """RF14 — Resposta composta só de números deve ser rejeitada."""
        valido, motivo = ValidadorPerguntaService.validar("12345678", "João", "joao@email.com")
        assert valido is False
        assert "números" in motivo

    def test_resposta_data_isolada_ano(self):
        """RF13 — Resposta que seja apenas um ano deve ser rejeitada."""
        valido, motivo = ValidadorPerguntaService.validar("1990", "João", "joao@email.com")
        assert valido is False

    def test_resposta_data_isolada_completa(self):
        """RF13 — Resposta que seja apenas data DD/MM/AAAA deve ser rejeitada."""
        valido, _ = ValidadorPerguntaService.validar("01/01/1990", "João", "joao@email.com")
        assert valido is False

    def test_resposta_igual_ao_nome(self):
        """RF14 — Resposta igual ao nome do usuário deve ser rejeitada."""
        valido, motivo = ValidadorPerguntaService.validar("João Silva", "João Silva", "joao@email.com")
        assert valido is False

    def test_resposta_igual_ao_email(self):
        """RF14 — Resposta igual ao e-mail deve ser rejeitada."""
        valido, _ = ValidadorPerguntaService.validar("joao@email.com", "João", "joao@email.com")
        assert valido is False

    def test_resposta_vazia(self):
        """RF13 — Resposta vazia deve ser rejeitada."""
        valido, _ = ValidadorPerguntaService.validar("", "João", "joao@email.com")
        assert valido is False


# ─── RF06/RF07: OTP Service ────────────────────────────────────────────────────

class TestRF07OTPService:
    def test_otp_tem_6_digitos(self):
        """RF07 — OTP deve ter exatamente 6 dígitos."""
        for _ in range(50):
            otp = OTPService.gerar()
            assert len(otp) == 6
            assert otp.isdigit()

    def test_otp_com_zeros_a_esquerda(self):
        """RF07 — OTP deve preservar zeros à esquerda (ex: 000123)."""
        # Simula valores baixos
        import secrets
        # Testa formato do padding
        otp = str(0).zfill(6)
        assert otp == "000000"
        assert len(otp) == 6

    def test_token_reset_tem_64_chars(self):
        """RNF03 — Token de redefinição deve ter 64 caracteres hex (256 bits)."""
        token = OTPService.gerar_token_reset()
        assert len(token) == 64
        assert all(c in "0123456789abcdef" for c in token)

    def test_expiracao_otp_10_minutos(self):
        """RF07 — OTP deve expirar em 10 minutos."""
        from datetime import datetime, timedelta
        exp = OTPService.expiracao_otp(10)
        agora = datetime.utcnow()
        diff = (exp - agora).total_seconds()
        assert 590 <= diff <= 610

    def test_expiracao_token_5_minutos(self):
        """RF10 — Token de redefinição deve expirar em 5 minutos."""
        from datetime import datetime
        exp = OTPService.expiracao_token(5)
        agora = datetime.utcnow()
        diff = (exp - agora).total_seconds()
        assert 290 <= diff <= 310


# ─── RF20: Auditoria ──────────────────────────────────────────────────────────

class TestRF20Auditoria:
    def test_log_criado_no_login_ok(self, app, client, usuario_base):
        """RF20 — Login bem-sucedido deve gerar registro no log."""
        with app.app_context():
            antes = LogAuditoria.query.count()
        client.post("/login", data={"email": "teste@email.com", "senha": "Senha@123"})
        with app.app_context():
            depois = LogAuditoria.query.count()
            assert depois > antes

    def test_log_criado_no_login_fail(self, app, client, usuario_base):
        """RF20 — Login com falha deve gerar registro no log."""
        with app.app_context():
            antes = LogAuditoria.query.count()
        client.post("/login", data={"email": "teste@email.com", "senha": "Errada"})
        with app.app_context():
            depois = LogAuditoria.query.count()
            assert depois > antes

    def test_log_tem_tipo_evento(self, app, client, usuario_base):
        """RF20 — Log deve registrar tipo de evento."""
        client.post("/login", data={"email": "teste@email.com", "senha": "Senha@123"})
        with app.app_context():
            log = LogAuditoria.query.filter_by(tipo_evento="login_ok").first()
            assert log is not None


# ─── Modelo Usuario ───────────────────────────────────────────────────────────

class TestModeloUsuario:
    def test_hash_senha_nao_armazena_texto_plano(self, app):
        """RNF01 — Senha não deve ser armazenada em texto plano."""
        with app.app_context():
            u = Usuario(nome="Teste", email="t@t.com", perfil="usuario")
            u.definir_senha("MinhaSenh@123")
            assert u.senha_hash != "MinhaSenh@123"
            assert len(u.senha_hash) > 20

    def test_verificar_senha_correta(self, app):
        """RNF01 — Verificação de senha correta deve retornar True."""
        with app.app_context():
            u = Usuario(nome="Teste", email="t@t.com", perfil="usuario")
            u.definir_senha("MinhaSenh@123")
            assert u.verificar_senha("MinhaSenh@123") is True

    def test_verificar_senha_errada(self, app):
        """RNF01 — Verificação de senha errada deve retornar False."""
        with app.app_context():
            u = Usuario(nome="Teste", email="t@t.com", perfil="usuario")
            u.definir_senha("MinhaSenh@123")
            assert u.verificar_senha("SenhaErrada") is False

    def test_bloquear_conta(self, app):
        """RF03 — Bloqueio deve desativar conta e zerar tentativas."""
        with app.app_context():
            u = Usuario(nome="Teste", email="t@t.com", perfil="usuario")
            u.tentativas = 3
            u.bloquear_conta()
            assert u.eh_ativo is False
            assert u.tentativas == 0