"""
Módulo de autenticação com hash SHA-256
Gerencia registro e login de usuários com segurança
"""

import hashlib
import os
import json


class AuthManager:
    """Gerencia autenticação de usuários com SHA-256 + salt"""
    
    @staticmethod
    def generate_salt(length=16):
        """
        Gera um salt aleatório para hash
        
        Args:
            length: Tamanho do salt em bytes
            
        Returns:
            str: Salt em hexadecimal
        """
        return os.urandom(length).hex()
    
    @staticmethod
    def hash_password(password, salt=None):
        """
        Calcula hash SHA-256 de uma senha com salt
        
        Args:
            password: Senha em string
            salt: Salt em hexadecimal (gera novo se None)
            
        Returns:
            tuple: (salt, hash) - Ambos em hexadecimal
        """
        if salt is None:
            salt = AuthManager.generate_salt()
        
        # Converte salt de hex para bytes para concatenação
        salt_bytes = bytes.fromhex(salt)
        password_bytes = password.encode('utf-8')
        
        # SHA-256 com salt
        pwd_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password_bytes,
            salt_bytes,
            100000  # 100000 iterações para segurança
        )
        
        return salt, pwd_hash.hex()
    
    @staticmethod
    def verify_password(password, stored_salt, stored_hash):
        """
        Verifica se senha corresponde ao hash armazenado
        
        Args:
            password: Senha fornecida
            stored_salt: Salt armazenado em hexadecimal
            stored_hash: Hash armazenado em hexadecimal
            
        Returns:
            bool: True se senha está correta
        """
        _, computed_hash = AuthManager.hash_password(password, stored_salt)
        return computed_hash == stored_hash
    
    @staticmethod
    def hash_single(data):
        """
        Calcula SHA-256 direto sem salt (para integridade de dados)
        
        Args:
            data: Dados a hashear (string ou bytes)
            
        Returns:
            str: Hash SHA-256 em hexadecimal
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return hashlib.sha256(data).hexdigest()


class UserDatabase:
    """Gerencia persistência de usuários em JSON"""
    
    def __init__(self, filename='users.db'):
        """
        Inicializa banco de dados de usuários
        
        Args:
            filename: Arquivo JSON para armazenar usuários
        """
        self.filename = filename
        self.users = self._load_database()
    
    def _load_database(self):
        """Carrega usuários do arquivo JSON"""
        if os.path.exists(self.filename):
            try:
                with open(self.filename, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_database(self):
        """Salva usuários em arquivo JSON"""
        with open(self.filename, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def user_exists(self, username):
        """Verifica se usuário existe"""
        return username in self.users
    
    def register_user(self, username, password, public_key_pem):
        """
        Registra novo usuário
        
        Args:
            username: Nome do usuário
            password: Senha em texto
            public_key_pem: Chave pública RSA em PEM (bytes)
            
        Returns:
            bool: True se registrado com sucesso
        """
        if self.user_exists(username):
            return False
        
        salt, pwd_hash = AuthManager.hash_password(password)
        
        self.users[username] = {
            'salt': salt,
            'password_hash': pwd_hash,
            'public_key': public_key_pem.decode('utf-8') if isinstance(public_key_pem, bytes) else public_key_pem,
            'registered_at': str(__import__('datetime').datetime.now())
        }
        
        self._save_database()
        return True
    
    def authenticate_user(self, username, password):
        """
        Autentica usuário verificando senha
        
        Args:
            username: Nome do usuário
            password: Senha em texto
            
        Returns:
            bool: True se autenticação bem-sucedida
        """
        if not self.user_exists(username):
            return False
        
        user = self.users[username]
        return AuthManager.verify_password(
            password,
            user['salt'],
            user['password_hash']
        )
    
    def get_public_key(self, username):
        """Obtém chave pública de um usuário"""
        if self.user_exists(username):
            return self.users[username]['public_key']
        return None
    
    def get_user_info(self, username):
        """Obtém informações do usuário (sem senha)"""
        if self.user_exists(username):
            user = self.users[username].copy()
            del user['password_hash']
            del user['salt']
            return user
        return None
