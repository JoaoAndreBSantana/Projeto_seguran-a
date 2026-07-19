"""
Servidor de Chat Seguro
Roteador central de mensagens entre clientes
"""

import socket
import threading
import json
import logging
from datetime import datetime
from auth import UserDatabase, AuthManager
from crypto_utils import RSACrypto

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - SERVER - %(message)s'
)
logger = logging.getLogger(__name__)


class SecureChatServer:
    """Servidor principal que gerencia conexões e mensagens"""
    
    def __init__(self, host='localhost', port=5555):
        """
        Inicializa servidor
        
        Args:
            host: Endereço para escutar
            port: Porta TCP
        """
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}  # {username: {'socket': ..., 'address': ...}}
        self.db = UserDatabase('users.db')
        self.lock = threading.Lock()
        
        logger.info(f"Servidor inicializado em {host}:{port}")
    
    def start(self):
        """Inicia servidor e aceita conexões"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        
        logger.info(f"Servidor escutando em {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, address = self.server_socket.accept()
                logger.info(f"Nova conexão de {address}")
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            logger.info("Encerrando servidor...")
            self.shutdown()
    
    def handle_client(self, client_socket, address):
        """Gerencia conexão de um cliente"""
        username = None
        
        try:
            # Etapa 1: Autenticação
            auth_request = self._receive_message(client_socket)
            if not auth_request:
                return
            
            action = auth_request.get('action')
            
            if action == 'register':
                username = self._handle_register(client_socket, auth_request)
            elif action == 'login':
                username = self._handle_login(client_socket, auth_request)
            else:
                self._send_message(client_socket, {'status': 'error', 'message': 'Ação inválida'})
                return
            
            if not username:
                return
            
            # Registra cliente conectado
            with self.lock:
                self.clients[username] = {
                    'socket': client_socket,
                    'address': address,
                    'connected_at': datetime.now()
                }
            
            logger.info(f"Usuário '{username}' autenticado de {address}")
            self._send_message(client_socket, {'status': 'authenticated', 'username': username})
            
            # Etapa 2: Roteamento de mensagens
            while True:
                message = self._receive_message(client_socket)
                if not message:
                    break
                
                if message.get('type') == 'message':
                    self._route_message(username, message)
                elif message.get('type') == 'get_users':
                    self._send_online_users(client_socket)
                elif message.get('type') == 'get_public_key':
                    self._send_public_key(client_socket, message.get('target'))
        
        except Exception as e:
            logger.error(f"Erro ao processar cliente: {e}")
        
        finally:
            # Remove cliente ao desconectar
            if username:
                with self.lock:
                    if username in self.clients:
                        del self.clients[username]
                logger.info(f"Usuário '{username}' desconectado")
            
            try:
                client_socket.close()
            except:
                pass
    
    def _handle_register(self, client_socket, request):
        """Processa registro de novo usuário"""
        username = request.get('username', '').strip()
        password = request.get('password', '')
        public_key = request.get('public_key')
        
        if not username or not password or not public_key:
            self._send_message(client_socket, {'status': 'error', 'message': 'Dados incompletos'})
            return None
        
        if self.db.user_exists(username):
            self._send_message(client_socket, {'status': 'error', 'message': 'Usuário já existe'})
            return None
        
        success = self.db.register_user(username, password, public_key.encode() if isinstance(public_key, str) else public_key)
        
        if success:
            logger.info(f"Novo usuário registrado: {username}")
            self._send_message(client_socket, {'status': 'registered', 'username': username})
            return username
        else:
            self._send_message(client_socket, {'status': 'error', 'message': 'Falha ao registrar'})
            return None
    
    def _handle_login(self, client_socket, request):
        """Processa login de usuário existente"""
        username = request.get('username', '').strip()
        password = request.get('password', '')
        
        if not username or not password:
            self._send_message(client_socket, {'status': 'error', 'message': 'Usuário ou senha vazia'})
            return None
        
        if not self.db.authenticate_user(username, password):
            self._send_message(client_socket, {'status': 'error', 'message': 'Autenticação falhou'})
            logger.warning(f"Tentativa de login falhada para: {username}")
            return None
        
        logger.info(f"Login bem-sucedido: {username}")
        return username
    
    def _route_message(self, sender, message):
        """Roteia mensagem para destinatário"""
        target = message.get('target')
        
        with self.lock:
            if target not in self.clients:
                # Envia notificação de usuário offline ao remetente
                if sender in self.clients:
                    self._send_message(
                        self.clients[sender]['socket'],
                        {'status': 'error', 'message': f'Usuário {target} offline'}
                    )
                return
            
            # Encaminha mensagem para destinatário
            try:
                self._send_message(
                    self.clients[target]['socket'],
                    {
                        'type': 'incoming_message',
                        'from': sender,
                        'encrypted_key': message.get('encrypted_key'),
                        'iv': message.get('iv'),
                        'ciphertext': message.get('ciphertext'),
                        'timestamp': datetime.now().isoformat()
                    }
                )
                logger.info(f"Mensagem roteada: {sender} -> {target}")
            except Exception as e:
                logger.error(f"Erro ao rotear mensagem: {e}")
    
    def _send_online_users(self, client_socket):
        """Envia lista de usuários online"""
        with self.lock:
            users = list(self.clients.keys())
        
        self._send_message(client_socket, {
            'type': 'users_list',
            'users': users
        })
    
    def _send_public_key(self, client_socket, target):
        """Envia chave pública de um usuário"""
        if not target:
            self._send_message(client_socket, {'status': 'error', 'message': 'Target não especificado'})
            return
        
        public_key = self.db.get_public_key(target)
        
        if not public_key:
            self._send_message(client_socket, {'status': 'error', 'message': f'Usuário {target} não encontrado'})
            return
        
        self._send_message(client_socket, {
            'type': 'public_key',
            'username': target,
            'public_key': public_key
        })
    
    def _send_message(self, socket, data):
        """Envia mensagem JSON ao cliente"""
        try:
            message = json.dumps(data).encode('utf-8')
            socket.sendall(message + b'\n')
        except Exception as e:
            logger.error(f"Erro ao enviar mensagem: {e}")
    
    def _receive_message(self, socket):
        """Recebe mensagem JSON do cliente"""
        try:
            buffer = b''
            while b'\n' not in buffer:
                chunk = socket.recv(4096)
                if not chunk:
                    return None
                buffer += chunk
            
            message_bytes = buffer.split(b'\n')[0]
            return json.loads(message_bytes.decode('utf-8'))
        except Exception as e:
            logger.error(f"Erro ao receber mensagem: {e}")
            return None
    
    def shutdown(self):
        """Encerra servidor gracefully"""
        if self.server_socket:
            self.server_socket.close()


def main():
    """Função principal para iniciar servidor"""
    server = SecureChatServer(host='localhost', port=5555)
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("Servidor interrompido pelo usuário")
    finally:
        server.shutdown()


if __name__ == '__main__':
    main()
