# Chat Seguro com Criptografia Híbrida

Sistema de mensagens em rede que demonstra conceitos de criptografia: **RSA + AES**, **SHA-256** e **Sockets TCP**.
Link Youtube: https://youtu.be/mdzB8XwtLcM?si=j1Y-z8RlDF08kyNe

## 🔐 Funcionalidades

### ✓ Autenticação com Hash
- Login seguro com **SHA-256 + Salt**
- Senhas nunca são armazenadas em texto claro
- 100.000 iterações PBKDF2 para segurança

### ✓ Troca de Chaves RSA
- Cada usuário gera par de chaves **RSA-2048**
- Chaves públicas trocadas para estabelecer canal seguro
- Servidor armazena apenas chaves públicas

### ✓ Criptografia AES
- Mensagens criptografadas com **AES-256-CBC**
- Chave AES gerada aleatoriamente para cada mensagem
- IV (Initialization Vector) aleatório para segurança

### ✓ Comunicação por Sockets
- Servidor central roteia mensagens
- Clientes conectam via **TCP/IP**
- Protocolo JSON para estruturação de dados

## 📁 Estrutura de Arquivos

```
secure_chat/
├── server.py           # Servidor de roteamento
├── client.py           # Cliente com interface
├── crypto_utils.py     # RSA e AES
├── auth.py             # Autenticação SHA-256
├── users.db            # Database JSON (criado automaticamente)
├── requirements.txt    # Dependências
└── README.md          # Este arquivo
```

## 🚀 Como Usar

### Instalação

```bash
pip install -r requirements.txt
```

### Iniciar Servidor

```bash
python server.py
```

Saída esperada:
```
2025-07-19 10:00:00 - SERVER - Servidor inicializado em localhost:5555
2025-07-19 10:00:00 - SERVER - Servidor escutando em localhost:5555
```

### Iniciar Cliente (em outro terminal)

```bash
python client.py
```

### Primeiro Uso (Registrar)

```
=== BEM-VINDO AO CHAT SEGURO ===
1. Novo usuário
2. Login

Opção: 1
=== REGISTRO DE NOVO USUÁRIO ===
Nome de usuário: alice
Senha: 
Gerando chaves RSA (2048 bits)...
✓ Usuário 'alice' registrado com sucesso
✓ Login bem-sucedido como 'alice'
```

### Menu Principal

```
=== CHAT SEGURO ===
1. Listar usuários online
2. Enviar mensagem
3. Ver mensagens recebidas
4. Sair

Opção: 1
=== USUÁRIOS ONLINE (2) ===
  • alice (você)
  • bob
```

### Enviar Mensagem Criptografada

```
Opção: 2
Nome do destinatário: bob
Mensagem para bob: Olá Bob! Mensagem segura
✓ Mensagem enviada para bob
```

A mensagem é criptografada em:
1. **AES-256-CBC** (chave simétrica aleatória)
2. **RSA-2048** (chave AES → criptografada com chave pública do Bob)

Bob recebe automaticamente:
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📨 MENSAGEM DE ALICE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Olá Bob! Mensagem segura
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## 🔄 Fluxo Técnico

### Autenticação (Login)

```
1. Cliente envia: username + SHA-256(senha + salt)
2. Servidor verifica hash armazenado
3. Se correto, gera chaves RSA do cliente
4. Servidor armazena chave pública para mensagens
```

### Troca de Chaves

```
1. Cliente A solicita chave pública de B ao servidor
2. Servidor retorna public_key_B
3. Cliente A pode agora criptografar para B
```

### Envio de Mensagem Segura

```
1. Cliente A gera chave AES-256 aleatória
2. Criptografa mensagem: AES-256-CBC(msg, key)
3. Criptografa chave: RSA(aes_key, public_key_B)
4. Envia ao servidor: {encrypted_key, iv, ciphertext}
5. Servidor roteia para Cliente B
6. Cliente B descriptografa:
   - RSA(encrypted_key, private_key_B) → aes_key
   - AES(ciphertext, aes_key) → mensagem
```

## 📊 Fluxo de Comunicação Segura

```
┌─────────────────────────────────────────────────────┐
│ Cliente Alice                                       │
├─────────────────────────────────────────────────────┤
│ 1. Digita mensagem                                 │
│ 2. Gera IV aleatório (16 bytes)                    │
│ 3. Criptografa: AES(msg, aes_key, IV)             │
│ 4. Obtém public_key_bob do servidor                │
│ 5. Criptografa chave: RSA(aes_key, pub_bob)       │
│ 6. Envia: {encrypted_key, iv, ciphertext}          │
└────────────────┬────────────────────────────────────┘
                 │
         ┌───────▼────────┐
         │ Servidor       │
         │ ────────────   │
         │ • Autentica   │
         │ • Roteia      │
         │ • Armazena    │
         └───────┬────────┘
                 │
┌────────────────▼────────────────────────────────────┐
│ Cliente Bob                                         │
├─────────────────────────────────────────────────────┤
│ 1. Recebe: {encrypted_key, iv, ciphertext}          │
│ 2. Descriptografa: RSA(encrypted_key, priv_bob)    │
│    → obtém aes_key                                 │
│ 3. Descriptografa: AES(ciphertext, aes_key, iv)   │
│    → obtém mensagem original                       │
│ 4. Exibe mensagem                                  │
└─────────────────────────────────────────────────────┘
```

## 🔑 Conceitos Criptográficos

### SHA-256 (Autenticação)
- **Hash**: `SHA-256(password + salt)` com 100.000 iterações
- **Salt**: 16 bytes aleatórios por usuário
- **Uso**: Armazenamento seguro de senhas

### RSA-2048 (Assimétrica)
- **Chave Privada**: Mantida segura no cliente
- **Chave Pública**: Distribuída para outros usuários
- **Uso**: Criptografar chave AES para destinatário específico
- **Padding**: OAEP para segurança contra ataques

### AES-256-CBC (Simétrica)
- **Modo**: CBC (Cipher Block Chaining)
- **Tamanho**: 256 bits (32 bytes)
- **IV**: 128 bits aleatório por mensagem
- **Uso**: Criptografar conteúdo da mensagem rapidamente

## 🧪 Testes

### Teste 1: Registro e Login

```bash
# Terminal 1: Inicia servidor
python server.py

# Terminal 2: Primeiro cliente (Alice)
python client.py
# Seleciona: 1 (Novo usuário)
# Username: alice
# Senha: senha123

# Terminal 3: Segundo cliente (Bob)
python client.py
# Seleciona: 2 (Login)
# Username: bob  # Registre primeiro em outro terminal
# Senha: senha456
```

### Teste 2: Troca de Mensagens

1. Alice: Menu → 1 (Listar usuários) → Verifica Bob online
2. Alice: Menu → 2 (Enviar) → Destinatário: bob → Escreve mensagem
3. Bob: Recebe automaticamente mensagem descriptografada
4. Bob: Menu → 2 (Enviar) → Destinatário: alice → Responde
5. Alice: Recebe resposta automaticamente

### Teste 3: Segurança

- Use `Wireshark` para capturar tráfego
- Observe que mensagens são incompreensíveis (hexadecimal)
- Chaves privadas nunca trafegam pela rede
- Hashes de senha protegem conta contra roubo de banco de dados

## ⚠️ Segurança

### ✓ O que está seguro
- Mensagens são criptografadas
- Senhas são hasheadas com salt
- Chaves privadas nunca são transmitidas
- IV aleatório para cada mensagem AES

### ⚠️ Limitações (Para ambiente de aprendizado)
- Sem verificação de certificados
- Sem sincronização de relógio para timestamps
- Sem compressão antes de criptografia
- Sem proteção contra replay attacks

## 📚 Referências

- [Cryptography Library](https://cryptography.io/)
- Chapter 3 - Criptografia (Apostila da disciplina)
- RFC 3394: AES Key Wrap Algorithm
- NIST SP 800-38A: Recommendation for Block Cipher Modes

## 👥 Autor

Projeto desenvolvido como desafio final da disciplina de Segurança da Informação.

> "Criptografia é como um cofre: sem a chave correta, o conteúdo é inútil"
