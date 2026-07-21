from flask import Flask, render_template, request
from flask_socketio import SocketIO
import threading

# Importa as suas classes originais
from client import SecureChatClient
from crypto_utils import RSACrypto, AESCrypto

app = Flask(__name__)
app.config['SECRET_KEY'] = 'uma_chave_secreta_qualquer'
socketio = SocketIO(app)

# Dicionário para guardar uma conexão diferente para CADA aba do navegador
usuarios_web = {}

def background_thread(sid):
    """Fica lendo a fila de mensagens recebidas APENAS para o usuário desta aba"""
    meu_cliente = usuarios_web.get(sid)
    if not meu_cliente: return

    while meu_cliente.running:
        try:
            response = meu_cliente.message_queue.get(timeout=1)
            
            if response.get('type') == 'incoming_message':
                tamanho_antes = len(meu_cliente.received_messages)
                
                # Descriptografa a mensagem
                meu_cliente._process_incoming_message(response)
                
                # Se deu certo, manda o texto limpo SÓ para a aba correta (to=sid)
                if len(meu_cliente.received_messages) > tamanho_antes:
                    ultima_msg = meu_cliente.received_messages[-1]
                    socketio.emit('nova_mensagem', {
                        'remetente': ultima_msg['from'],
                        'texto': ultima_msg['text']
                    }, to=sid)
        except:
            continue

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('tentar_login')
def handle_login(data):
    sid = request.sid  # Pega o ID único desta aba do navegador
    username = data.get('username')
    password = data.get('password')
    action = data.get('action')
    
    # 1. Cria um cliente TCP exclusivo para essa aba
    meu_cliente = SecureChatClient(host='localhost', port=5555)
    usuarios_web[sid] = meu_cliente
    
    try:
        meu_cliente.connect()
    except Exception as e:
        socketio.emit('login_resposta', {'sucesso': False, 'mensagem': f'Falha ao conectar no servidor (5555): {e}'}, to=sid)
        return
            
    meu_cliente.private_key, meu_cliente.public_key = RSACrypto.generate_key_pair(2048)
    public_key_pem = RSACrypto.serialize_public_key(meu_cliente.public_key)
    
    meu_cliente._send_message({
        'action': action,
        'username': username,
        'password': password,
        'public_key': public_key_pem.decode('utf-8')
    })
    
    response = meu_cliente._receive_message()
    
    if response and response.get('status') in ['authenticated', 'registered']:
        meu_cliente.username = username
        
        # Inicia a thread escutando apenas esta conexão
        threading.Thread(target=background_thread, args=(sid,), daemon=True).start()
        
        socketio.emit('login_resposta', {'sucesso': True, 'username': username}, to=sid)
    else:
        mensagem_erro = response.get('message', 'Erro desconhecido.') if response else 'O servidor não respondeu a tempo.'
        socketio.emit('login_resposta', {'sucesso': False, 'mensagem': mensagem_erro}, to=sid)

@socketio.on('listar_usuarios')
def handle_listar():
    sid = request.sid
    meu_cliente = usuarios_web.get(sid)
    if not meu_cliente: return

    meu_cliente._send_message({'type': 'get_users'})
    response = meu_cliente._receive_message()
    
    if response and response.get('type') == 'users_list':
        usuarios = response.get('users', [])
        socketio.emit('usuarios_online', {'users': usuarios}, to=sid)

@socketio.on('enviar_mensagem')
def handle_message(data):
    sid = request.sid
    meu_cliente = usuarios_web.get(sid)
    if not meu_cliente: return

    target = data.get('target')
    message_text = data.get('message')
    
    meu_cliente._send_message({'type': 'get_public_key', 'target': target})
    response = meu_cliente._receive_message()
    
    if not response or response.get('type') != 'public_key':
        return
        
    recipient_public_key_pem = response.get('public_key').encode('utf-8')
    recipient_public_key = RSACrypto.deserialize_public_key(recipient_public_key_pem)
    
    if target not in meu_cliente.session_keys:
        aes_key = AESCrypto.generate_key()
        meu_cliente.session_keys[target] = aes_key
    else:
        aes_key = meu_cliente.session_keys[target]
        
    iv, ciphertext = AESCrypto.encrypt(aes_key, message_text)
    encrypted_key = RSACrypto.encrypt(recipient_public_key, aes_key)
    
    meu_cliente._send_message({
        'type': 'message',
        'target': target,
        'encrypted_key': encrypted_key.hex(),
        'iv': iv.hex(),
        'ciphertext': ciphertext.hex()
    })
    
    socketio.emit('nova_mensagem', {'remetente': 'Você', 'texto': message_text}, to=sid)

# Limpa a memória quando o usuário fechar a aba
@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    if sid in usuarios_web:
        usuarios_web[sid].running = False
        del usuarios_web[sid]

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=True, allow_unsafe_werkzeug=True)