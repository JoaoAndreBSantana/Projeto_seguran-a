"""
Módulo de utilitários criptográficos
Implementa RSA e AES para comunicação segura
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


class RSACrypto:
    """Gerencia operações com criptografia RSA assimétrica"""
    
    @staticmethod
    def generate_key_pair(key_size=2048):
        """
        Gera um par de chaves RSA (pública + privada)
        
        Args:
            key_size: Tamanho da chave em bits (padrão: 2048)
            
        Returns:
            tuple: (chave_privada, chave_pública)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_private_key(private_key):
        """Serializa chave privada para PEM"""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    @staticmethod
    def serialize_public_key(public_key):
        """Serializa chave pública para PEM"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def deserialize_public_key(public_key_pem):
        """Desserializa chave pública de PEM"""
        return serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
    
    @staticmethod
    def deserialize_private_key(private_key_pem):
        """Desserializa chave privada de PEM"""
        return serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
    
    @staticmethod
    def encrypt(public_key, plaintext):
        """
        Criptografa mensagem com chave pública RSA
        
        Args:
            public_key: Chave pública RSA
            plaintext: Mensagem em bytes
            
        Returns:
            bytes: Mensagem criptografada
        """
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    @staticmethod
    def decrypt(private_key, ciphertext):
        """
        Descriptografa mensagem com chave privada RSA
        
        Args:
            private_key: Chave privada RSA
            ciphertext: Mensagem criptografada em bytes
            
        Returns:
            bytes: Mensagem descriptografada
        """
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext


class AESCrypto:
    """Gerencia operações com criptografia AES simétrica"""
    
    @staticmethod
    def generate_key():
        """
        Gera chave AES-256 aleatória
        
        Returns:
            bytes: Chave AES de 32 bytes (256 bits)
        """
        return os.urandom(32)
    
    @staticmethod
    def encrypt(key, plaintext):
        """
        Criptografa mensagem com AES-256 em modo CBC
        
        Args:
            key: Chave AES de 32 bytes
            plaintext: Mensagem em bytes ou string
            
        Returns:
            tuple: (iv, ciphertext) - IV necessário para descriptografia
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Gera IV aleatório para cada mensagem
        iv = os.urandom(16)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Padding PKCS7
        block_size = 16
        padding_length = block_size - (len(plaintext) % block_size)
        plaintext = plaintext + bytes([padding_length] * padding_length)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return iv, ciphertext
    
    @staticmethod
    def decrypt(key, iv, ciphertext):
        """
        Descriptografa mensagem com AES-256 em modo CBC
        
        Args:
            key: Chave AES de 32 bytes
            iv: IV usado na criptografia
            ciphertext: Mensagem criptografada em bytes
            
        Returns:
            str: Mensagem descriptografada
        """
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding PKCS7
        padding_length = plaintext[-1]
        plaintext = plaintext[:-padding_length]
        
        return plaintext.decode('utf-8')
