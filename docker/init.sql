CREATE DATABASE IF NOT EXISTS recuperacao_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE recuperacao_db;

CREATE TABLE IF NOT EXISTS usuario (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    senha_hash VARCHAR(255) NOT NULL,
    perfil ENUM('admin', 'usuario', 'analista') NOT NULL DEFAULT 'usuario',
    eh_ativo BOOLEAN NOT NULL DEFAULT TRUE,
    tentativas INT NOT NULL DEFAULT 0,
    criado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pergunta_confiavel (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    texto_pergunta VARCHAR(300) NOT NULL,
    resposta_hash VARCHAR(255) NOT NULL,
    validado BOOLEAN NOT NULL DEFAULT FALSE,
    criado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES usuario(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS recuperacao (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    otp_code VARCHAR(6),
    otp_expira_em DATETIME,
    pergunta_id INT,
    reset_token VARCHAR(255),
    expiracao_em DATETIME,
    tentativas INT NOT NULL DEFAULT 0,
    estagio ENUM('otp_pendente', 'pergunta_pendente', 'concluido', 'bloqueado') NOT NULL DEFAULT 'otp_pendente',
    criado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES usuario(id) ON DELETE CASCADE,
    FOREIGN KEY (pergunta_id) REFERENCES pergunta_confiavel(id)
);

CREATE TABLE IF NOT EXISTS log_auditoria (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    tipo_fluxo ENUM('proposto', 'link_only', 'otp_only', 'pergunta_only') DEFAULT NULL,
    tipo_evento VARCHAR(50) NOT NULL,
    endereco_ip VARCHAR(45),
    criado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES usuario(id) ON DELETE SET NULL
);

-- Usuário admin padrão (senha: Admin@123)
INSERT IGNORE INTO usuario (nome, email, senha_hash, perfil) VALUES
('Administrador', 'admin@sistema.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TqrZS.OI3bRwHmLH5gEXbD4YtxEO', 'admin');