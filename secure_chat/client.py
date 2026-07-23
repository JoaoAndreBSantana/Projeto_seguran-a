"""
Cliente de Chat Seguro
Interface de usuário para comunicação segura
"""

import socket
import json
import threading
import sys
import time
from getpass import getpass
from queue import Queue
from crypto_utils import RSACrypto, AESCrypto
from auth import AuthManager


class SecureChatClient:
    """Cliente para chat seguro com criptografia híbrida"""
    
    def __init__(self, host='localhost', port=5555):
        """
        Inicializa cliente
        
        Args:
            host: Endereço do servidor
            port: Porta do servidor
        """
        self.host = host
        self.port = port
        self.socket = None
        self.username = None
        self.private_key = None
        self.public_key = None
        self.session_keys = {}  # {username: aes_key}
        self.received_messages = []
        self.running = True
        self.message_queue = Queue()  # Fila de mensagens recebidas
        self.response_event = threading.Event()  # Sinal para respostas síncronas
        self.last_response = None  # Armazena última resposta síncrona
    
    def connect(self):
        """Conecta ao servidor"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"✓ Conectado ao servidor {self.host}:{self.port}")
            
            # Inicia thread de leitura do socket
            reader_thread = threading.Thread(target=self._socket_reader, daemon=True)
            reader_thread.start()
            
            return True
        except Exception as e:
            print(f"✗ Erro ao conectar: {e}")
            return False
    
    def _send_message(self, data):
        """Envia mensagem JSON ao servidor"""
        try:
            message = json.dumps(data).encode('utf-8')
            self.socket.sendall(message + b'\n')
        except Exception as e:
            print(f"✗ Erro ao enviar: {e}")
    
    def _receive_message(self):
        """Recebe mensagem JSON do servidor (síncrono - aguarda resposta)"""
        self.response_event.clear()
        if self.response_event.wait(timeout=10):
            response = self.last_response
            self.last_response = None
            return response
        return None
    
    def _socket_reader(self):
        """Thread que lê continuamente do socket e distribui mensagens"""
        try:
            buffer = b''
            while self.running:
                chunk = self.socket.recv(4096)
                if not chunk:
                    break
                
                buffer += chunk
                
                # Processa todas as linhas completas no buffer
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    try:
                        message = json.loads(line.decode('utf-8'))
                        # Armazena no histórico de mensagens recebidas
                        if message.get('type') == 'incoming_message':
                            self.message_queue.put(message)
                        else:
                            # Respostas síncronas
                            self.last_response = message
                            self.response_event.set()
                    except json.JSONDecodeError:
                        print(f"✗ Erro ao decodificar JSON: {line}")
        except Exception as e:
            if self.running:
                print(f"✗ Erro na leitura do socket: {e}")
        finally:
            self.running = False
    
    def register(self):
        """Registra novo usuário"""
        print("\n=== REGISTRO DE NOVO USUÁRIO ===")
        username = input("Nome de usuário: ").strip()
        
        if not username:
            print("✗ Nome de usuário vazio")
            return False
        
        password = getpass("Senha: ")
        if not password:
            print("✗ Senha vazia")
            return False
        
        # Gera par de chaves RSA
        print("Gerando chaves RSA (2048 bits)...")
        self.private_key, self.public_key = RSACrypto.generate_key_pair(2048)
        public_key_pem = RSACrypto.serialize_public_key(self.public_key)
        
        # Envia requisição de registro
        self._send_message({
            'action': 'register',
            'username': username,
            'password': password,
            'public_key': public_key_pem.decode('utf-8')
        })
        
        response = self._receive_message()
        if response and response.get('status') == 'registered':
            self.username = username
            print(f"✓ Usuário '{username}' registrado com sucesso")
            return True
        else:
            print(f"✗ Falha no registro: {response.get('message', 'Desconhecida')}")
            return False
    
    def login(self):
        """Faz login de usuário existente"""
        print("\n=== LOGIN ===")
        username = input("Nome de usuário: ").strip()
        
        if not username:
            print("✗ Nome de usuário vazio")
            return False
        
        password = getpass("Senha: ")
        if not password:
            print("✗ Senha vazia")
            return False
        
        # Gera par de chaves RSA
        print("Gerando chaves RSA (2048 bits)...")
        self.private_key, self.public_key = RSACrypto.generate_key_pair(2048)
        public_key_pem = RSACrypto.serialize_public_key(self.public_key)
        
        # Envia requisição de login
        self._send_message({
            'action': 'login',
            'username': username,
            'password': password,
            'public_key': public_key_pem.decode('utf-8')
        })
        
        response = self._receive_message()
        if response and response.get('status') == 'authenticated':
            self.username = username
            print(f"✓ Login bem-sucedido como '{username}'")
            return True
        else:
            print(f"✗ Falha no login: {response.get('message', 'Desconhecida')}")
            return False
    
    def list_users(self):
        """Lista usuários online"""
        self._send_message({'type': 'get_users'})
        response = self._receive_message()
        
        if response and response.get('type') == 'users_list':
            users = response.get('users', [])
            print(f"\n=== USUÁRIOS ONLINE ({len(users)}) ===")
            for user in users:
                status = "(você)" if user == self.username else ""
                print(f"  • {user} {status}")
        else:
            print("✗ Erro ao obter lista de usuários")
    
    def send_message(self, target):
        """Envia mensagem criptografada para usuário"""
        if target == self.username:
            print("✗ Não é possível enviar mensagem para si mesmo")
            return
        
        # Obtém chave pública do destinatário
        self._send_message({'type': 'get_public_key', 'target': target})
        response = self._receive_message()
        
        if not response or response.get('type') != 'public_key':
            print(f"✗ Não foi possível obter chave pública de {target}")
            return
        
        recipient_public_key_pem = response.get('public_key').encode('utf-8')
        
        recipient_public_key = RSACrypto.deserialize_public_key(recipient_public_key_pem)
        
        # Escreve mensagem
        message_text = input(f"\nMensagem para {target}: ").strip()
        if not message_text:
            print("✗ Mensagem vazia")
            return
        
        # Gera chave AES para esta sessão
        if target not in self.session_keys:
            aes_key = AESCrypto.generate_key()
            self.session_keys[target] = aes_key
        else:
            aes_key = self.session_keys[target]
        
        # Criptografa mensagem com AES
        iv, ciphertext = AESCrypto.encrypt(aes_key, message_text)
        
        # Criptografa chave AES com RSA público do destinatário
        encrypted_key = RSACrypto.encrypt(recipient_public_key, aes_key)
        
        # Envia mensagem ao servidor
        self._send_message({
            'type': 'message',
            'target': target,
            'encrypted_key': encrypted_key.hex(),
            'iv': iv.hex(),
            'ciphertext': ciphertext.hex()
        })
        
        print(f"✓ Mensagem enviada para {target}")
    
    def receive_messages(self):
        """Thread que processa mensagens recebidas da fila"""
        while self.running:
            try:
                response = self.message_queue.get(timeout=1)
                if response.get('type') == 'incoming_message':
                    self._process_incoming_message(response)
            except:
                continue
    
    def _process_incoming_message(self, response):
        """Processa mensagem recebida"""
        sender = response.get('from')
        encrypted_key_hex = response.get('encrypted_key')
        iv_hex = response.get('iv')
        ciphertext_hex = response.get('ciphertext')
        
        try:
            # Descriptografa chave AES com chave privada RSA
            encrypted_key = bytes.fromhex(encrypted_key_hex)
            aes_key = RSACrypto.decrypt(self.private_key, encrypted_key)
            
            # Descriptografa mensagem com AES
            iv = bytes.fromhex(iv_hex)
            ciphertext = bytes.fromhex(ciphertext_hex)
            plaintext = AESCrypto.decrypt(aes_key, iv, ciphertext)
            
            # Armazena chave da sessão
            self.session_keys[sender] = aes_key
            
            # Exibe mensagem
            timestamp = response.get('timestamp', '')
            print(f"\n\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"📨 MENSAGEM DE {sender.upper()}")
            print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
            print(f"{plaintext}")
            print(f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
            
            self.received_messages.append({
                'from': sender,
                'text': plaintext,
                'timestamp': timestamp
            })
        
        except Exception as e:
            print(f"✗ Erro ao descriptografar mensagem: {type(e).__name__}: {e}")
    
    def show_menu(self):
        """Exibe menu interativo"""
        while self.running:
            print("\n=== CHAT SEGURO ===")
            print("1. Listar usuários online")
            print("2. Enviar mensagem")
            print("3. Ver mensagens recebidas")
            print("4. Sair")
            
            choice = input("\nOpção: ").strip()
            
            if choice == '1':
                self.list_users()
            elif choice == '2':
                target = input("Nome do destinatário: ").strip()
                if target:
                    self.send_message(target)
            elif choice == '3':
                self.show_received_messages()
            elif choice == '4':
                self.running = False
                break
            else:
                print("✗ Opção inválida")
    
    def show_received_messages(self):
        """Exibe histórico de mensagens recebidas"""
        if not self.received_messages:
            print("\nNenhuma mensagem recebida ainda")
            return
        
        print("\n=== HISTÓRICO DE MENSAGENS ===")
        for i, msg in enumerate(self.received_messages, 1):
            print(f"\n{i}. De: {msg['from']}")
            print(f"   {msg['text']}")
            print(f"   {msg['timestamp']}")
    
    def run(self):
        """Executa cliente"""
        if not self.connect():
            return
        
        print("\n=== BEM-VINDO AO CHAT SEGURO ===")
        print("1. Novo usuário")
        print("2. Login")
        
        choice = input("\nOpção: ").strip()
        
        if choice == '1':
            if not self.register():
                return
        elif choice == '2':
            if not self.login():
                return
        else:
            print("✗ Opção inválida")
            return
        
        # Inicia thread de recepção
        receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receiver_thread.start()
        
        # Menu interativo
        try:
            self.show_menu()
        except KeyboardInterrupt:
            print("\n\nDesconectando...")
        finally:
            self.running = False
            self.socket.close()
            print("✓ Desconectado")


def main():
    """Função principal"""
    client = SecureChatClient(host='localhost', port=5555)
    client.run()


if __name__ == '__main__':
    main()