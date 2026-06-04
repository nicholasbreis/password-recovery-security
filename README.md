# Password Recovery Security

Análise de segurança em fluxos de recuperação de senha para fins acadẽmicos.

## Sobre o projeto

Este projeto implementa e compara quatro fluxos de recuperação de senha, investigando o equilíbrio entre **segurança** e **usabilidade**:

| Fluxo | Descrição |
|-------|-----------|
| **Proposto** | OTP por e-mail (Etapa 1) + Pergunta confiável (Etapa 2) |
| Tradicional 1 | Link por e-mail isolado |
| Tradicional 2 | OTP isolado (sem segunda etapa) |
| Tradicional 3 | Pergunta de segurança isolada |

**Pergunta de pesquisa:** Um fluxo de recuperação em duas etapas obrigatórias consegue reduzir os riscos de sequestro de conta (*account takeover*) sem tornar o processo excessivamente complexo para o usuário?

---

## Tecnologias

- **Backend:** Python 3.11 + Flask
- **Banco de dados:** MySQL 8.0
- **Frontend:** HTML5, CSS3, JavaScript (Jinja2)
- **Testes:** Pytest + pytest-flask
- **Infraestrutura:** Docker + Docker Compose
- **E-mail (dev):** MailHog

---

---

## Como executar

### Pré-requisito

Instale o [Docker Desktop](https://www.docker.com/products/docker-desktop).

### 1. Clone o repositório

```bash
git clone https://github.com/SEU_USUARIO/password-recovery-security.git
cd password-recovery-security
```

### 2. Suba os containers

```bash
docker compose up --build
```

Na primeira execução o Docker baixa as imagens e configura o banco - aguarde até aparecer:

```
Running on http://0.0.0.0:5000
```

### 3. Acesse o sistema

| Serviço | URL |
|---------|-----|
| Sistema web | http://localhost:5000 |
| MailHog (e-mails) | http://localhost:8025 |

### 4. Usuário administrador padrão

```
E-mail: admin@sistema.local
Senha:  Admin@123
```

### 5. Para encerrar

```bash
docker compose down
```

---

## Executando os testes

Com os containers no ar, abra outro terminal e execute:

```bash
docker compose exec web pytest tests/test_modulo1.py -v
```

Resultado esperado:

```
28 passed in X.XXs
```

### Requisitos cobertos pelos testes

| Requisito | Descrição | Status |
|-----------|-----------|--------|
| RF01 | Registro de usuários | ✅ |
| RF02 | Autenticação por e-mail e senha | ✅ |
| RF03 | Bloqueio após 3 tentativas falhas | ✅ |
| RF07 | OTP de 6 dígitos, validade 10 min | ✅ |
| RF10 | Token de redefinição uso único, 5 min | ✅ |
| RF12 | Mínimo 3 perguntas confiáveis | ✅ |
| RF13 | Validação de qualidade da resposta | ✅ |
| RF14 | Rejeição de respostas triviais | ✅ |
| RF20 | Registro de eventos no log de auditoria | ✅ |
| RNF01 | Senhas armazenadas com bcrypt | ✅ |
| RNF03 | Token de redefinição com 256 bits de entropia | ✅ |

---

## Fluxo proposto - como funciona

```
Usuário informa e-mail
        ↓
[Etapa 1] Código OTP enviado por e-mail
          6 dígitos · válido por 10 min · máx. 3 tentativas
        ↓
[Etapa 2] Pergunta confiável selecionada aleatoriamente
          Resposta com mínimo 4 palavras · máx. 3 tentativas
        ↓
Link de redefinição enviado por e-mail
          256 bits de entropia · uso único · expira em 5 min
        ↓
Usuário redefine a senha → conta reativada
        ↓
Evento registrado no log de auditoria
```

### Critérios de qualidade das perguntas confiáveis (RF13, RF14)

As respostas são validadas antes de serem aceitas pelo sistema:

- ✅ Mínimo de 4 palavras
- ❌ Apenas números
- ❌ Data isolada (ex: `1990` ou `01/01/1990`)
- ❌ Igual ao nome do usuário
- ❌ Igual ao e-mail do usuário
- ❌ Vazia

---

## Perfis de usuário

| Perfil | Acesso |
|--------|--------|
| **Usuário** | Login, recuperação de senha, cadastro de perguntas confiáveis |
| **Administrador** | CRUD de usuários, bloqueio/desbloqueio de contas, políticas de senha |
| **Analista** | Visualização e exportação de logs de auditoria, comparativo entre fluxos |

---

## Segurança — decisões de implementação

| Mecanismo | Implementação | Entropia |
|-----------|---------------|----------|
| OTP (Etapa 1) | `secrets.randbelow(1_000_000)` com zfill(6) | ~20 bits - compensado pelo bloqueio após 3 tentativas e expiração de 10 min |
| Token de redefinição | `secrets.token_hex(32)` | 256 bits |
| Senhas | bcrypt com fator de custo 12 | - |
| Respostas das perguntas | bcrypt com fator de custo 12 | - |

---

## Licença

Projeto acadêmico

---

*Aluno: Nicholas Barcelos dos Reis · Professor: Frederico Schardong*
