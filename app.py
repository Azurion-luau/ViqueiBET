# app.py
import json
import os
import random
import time
from datetime import datetime

import firebase_admin
from firebase_admin import auth, credentials, firestore
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
import uuid # Para gerar códigos únicos

app = Flask(__name__)
# MUITO IMPORTANTE: Mude esta chave secreta para um valor complexo e único em produção!
# É usada para proteger as sessões do usuário.
app.secret_key = 'azurionkeysupremetoforeversave' # Chave secreta atualizada

# --- Configuração do Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Define a rota para onde redirecionar se o usuário não estiver logado

# --- Firebase Initialization ---
# Estas variáveis são tipicamente fornecidas pelo ambiente Canvas para uma configuração de backend.
# Em um aplicativo Flask local, você carregaria um arquivo de chave de conta de serviço.
# Para esta simulação, vamos tentar imitar como o Canvas pode passar a configuração.
# Assumindo que __firebase_config é uma string JSON de uma chave de conta de serviço.
firebase_config_str = os.environ.get('__firebase_config', '{}')
app_id = os.environ.get('__app_id', 'default-app-id') # Use um padrão se não for fornecido

db = None # Inicializa o cliente Firestore globalmente
firebase_initialized = False

try:
    firebase_config = json.loads(firebase_config_str)
    # Verifica se a configuração é um dicionário e se contém a chave 'type' com 'service_account'
    if firebase_config and isinstance(firebase_config, dict) and firebase_config.get("type") == "service_account":
        if not firebase_admin._apps: # Inicializa o Firebase apenas uma vez
            cred = credentials.Certificate(firebase_config)
            firebase_admin.initialize_app(cred)
            db = firestore.client()
            firebase_initialized = True
            print("Firebase Admin SDK inicializado com sucesso.")
        else:
            # Se já estiver inicializado (por exemplo, em um recarregamento do servidor de desenvolvimento)
            db = firestore.client()
            firebase_initialized = True
            print("Firebase Admin SDK já inicializado.")
    else:
        print("Configuração do Firebase ausente ou inválida (não é uma conta de serviço válida). Rodando sem persistência de dados no Firebase.")
except json.JSONDecodeError:
    print("Variável de ambiente '__firebase_config' não é um JSON válido. Rodando sem persistência de dados no Firebase.")
except Exception as e:
    print(f"Erro inesperado ao inicializar Firebase Admin SDK: {e}")
    print("Rodando sem persistência de dados devido ao erro.")


# --- Armazenamento de Usuários em Memória (Fallback) ---
# Este dicionário será usado se o Firebase não estiver inicializado.
_memory_users_db = {}
_memory_deposit_codes_db = {} # Novo para códigos de depósito em memória
USERS_JSON_FILE = 'users.json' # Define o nome do arquivo JSON para salvar os usuários
DEPOSIT_CODES_JSON_FILE = 'deposit_codes.json' # Novo arquivo JSON para códigos de depósito

def load_users_from_json():
    """Carrega os dados dos usuários de um arquivo JSON."""
    if os.path.exists(USERS_JSON_FILE) and os.path.getsize(USERS_JSON_FILE) > 0:
        try:
            with open(USERS_JSON_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                users = {}
                for email, user_data in data.items():
                    # Reconstruct User object from JSON data
                    user = User(
                        uid=user_data['id'], # Usa 'id' do JSON como uid para o modo de memória
                        email=user_data['email'],
                        is_admin=user_data.get('is_admin', False),
                        balance=user_data.get('balance', 1000.0),
                        card_info=user_data.get('card_info', {}),
                        personal_id=user_data.get('personal_id', {}),
                        password_hash=user_data.get('password_hash'), # Carrega a senha hasheada
                        is_banned=user_data.get('is_banned', False) # Carrega o status de banido
                    )
                    user.forced_game_outcome = user_data.get('forced_game_outcome', {'game_type': None, 'outcome': None})
                    users[email] = user
                return users
        except json.JSONDecodeError as e:
            print(f"Erro ao decodificar JSON de usuários: {e}")
            return {}
        except Exception as e:
            print(f"Erro ao carregar usuários de {USERS_JSON_FILE}: {e}")
            return {}
    return {}

def save_users_to_json(users_dict):
    """Salva os dados dos usuários em um arquivo JSON."""
    try:
        # Prepara os dados para serialização JSON (converte objetos User para dicionários)
        serializable_users = {}
        for email, user_obj in users_dict.items():
            user_data = {
                'id': user_obj.id, # Armazena uid/email como 'id'
                'email': user_obj.email,
                'is_admin': user_obj.is_admin,
                'balance': user_obj.balance,
                'card_info': user_obj.card_info,
                'personal_id': user_obj.personal_id,
                'forced_game_outcome': user_obj.forced_game_outcome,
                'password_hash': user_obj.password_hash, # Salva a senha hasheada para o modo de memória
                'is_banned': user_obj.is_banned # Salva o status de banido
            }
            serializable_users[email] = user_data
        
        with open(USERS_JSON_FILE, 'w', encoding='utf-8') as f:
            json.dump(serializable_users, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Erro ao salvar usuários em {USERS_JSON_FILE}: {e}")
        return False

def load_deposit_codes_from_json():
    """Carrega os códigos de depósito de um arquivo JSON."""
    if os.path.exists(DEPOSIT_CODES_JSON_FILE) and os.path.getsize(DEPOSIT_CODES_JSON_FILE) > 0:
        try:
            with open(DEPOSIT_CODES_JSON_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"Erro ao decodificar JSON de códigos de depósito: {e}")
            return {}
        except Exception as e:
            print(f"Erro ao carregar códigos de depósito de {DEPOSIT_CODES_JSON_FILE}: {e}")
            return {}
    return {}

def save_deposit_codes_to_json(codes_dict):
    """Salva os códigos de depósito em um arquivo JSON."""
    try:
        with open(DEPOSIT_JSON_FILE, 'w', encoding='utf-8') as f:
            json.dump(codes_dict, f, indent=4, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Erro ao salvar códigos de depósito em {DEPOSIT_CODES_JSON_FILE}: {e}")
        return False


# --- Classe User para Flask-Login (suporta Firebase e fallback em memória/JSON) ---
class User(UserMixin):
    def __init__(self, uid, email, is_admin=False, balance=1000.0, card_info=None, personal_id=None, password_hash=None, is_banned=False):
        self.id = uid # UID do Firebase Auth (se Firebase estiver ativo) ou email (se memória)
        self.email = email
        self.is_admin = is_admin
        self.balance = float(balance) # Garante que o saldo seja float
        self.card_info = card_info if card_info is not None else {}
        self.personal_id = personal_id if personal_id is not None else {}
        self.forced_game_outcome = {'game_type': None, 'outcome': None}
        self.password_hash = password_hash # Usado apenas para o modo de memória (não salvo no Firestore)
        self.is_banned = is_banned # Novo atributo para status de banido

    @staticmethod
    def get_user_doc_ref(uid):
        """Ajuda a obter uma referência de documento Firestore para um usuário."""
        if db:
            # Usando __app_id para multi-tenancy no ambiente Canvas
            return db.collection('artifacts').document(app_id).collection('users').document(uid).collection('data').document('profile')
        return None

    @staticmethod
    def get(identifier):
        """
        Carrega um usuário do Firestore (se inicializado) ou da memória/JSON.
        'identifier' pode ser UID (Firebase) ou email (memória).
        """
        if firebase_initialized:
            doc_ref = User.get_user_doc_ref(identifier) # identifier é o UID aqui
            if doc_ref:
                doc = doc_ref.get()
                if doc.exists:
                    data = doc.to_dict()
                    user = User(
                        uid=identifier, # UID é o id
                        email=data.get('email'),
                        is_admin=data.get('is_admin', False),
                        balance=data.get('balance', 1000.0),
                        card_info=data.get('card_info', {}),
                        personal_id=data.get('personal_id', {}),
                        is_banned=data.get('is_banned', False) # Carrega o status de banido
                    )
                    user.forced_game_outcome = data.get('forced_game_outcome', {'game_type': None, 'outcome': None})
                    return user
        else: # Fallback para modo de memória/JSON
            return _memory_users_db.get(identifier) # identifier é o email aqui
        return None

    def save(self):
        """Salva os dados do usuário atual no Firestore (se inicializado) ou na memória/JSON."""
        if firebase_initialized:
            doc_ref = User.get_user_doc_ref(self.id)
            if doc_ref:
                try:
                    doc_ref.set({
                        'email': self.email,
                        'is_admin': self.is_admin,
                        'balance': self.balance,
                        'card_info': self.card_info,
                        'personal_id': self.personal_id,
                        'forced_game_outcome': self.forced_game_outcome,
                        'is_banned': self.is_banned # Salva o status de banido
                    })
                    return True
                except Exception as e:
                    print(f"Erro ao salvar usuário {self.email} no Firestore: {e}")
                    return False
        else: # Salvar na memória e no arquivo JSON
            _memory_users_db[self.email] = self
            return save_users_to_json(_memory_users_db) # Chama a função de salvar no JSON
        return False

# Flask-Login user_loader
@login_manager.user_loader
def load_user(user_id_or_email): # user_id é o UID ou email dependendo do modo
    """
    Callback para recarregar o objeto User do user_id armazenado na sessão.
    """
    return User.get(user_id_or_email)

# Load users from JSON at startup if Firebase is not initialized
if not firebase_initialized:
    _memory_users_db = load_users_from_json()
    _memory_deposit_codes_db = load_deposit_codes_from_json()
    
# --- Pré-registro do Admin (ou busca no Firebase Auth / memória/JSON) ---
ADMIN_EMAIL = "admin@voxelix.gg"
ADMIN_PASSWORD = "bikeadm%" # Senha de administrador atualizada

if firebase_initialized:
    try:
        # Tenta obter o usuário admin pelo email no Firebase Auth
        admin_auth_user = auth.get_user_by_email(ADMIN_EMAIL)
        # Tenta obter o perfil do admin no Firestore
        admin_firestore_profile = User.get(admin_auth_user.uid) # Passa o UID
        if not admin_firestore_profile:
            # Se o usuário Auth existe mas o perfil Firestore não, cria-o
            admin_user = User(admin_auth_user.uid, ADMIN_EMAIL, is_admin=True)
            admin_user.save()
            print(f"Perfil de administrador '{ADMIN_EMAIL}' criado no Firestore para UID {admin_auth_user.uid}.")
        else:
            print(f"Usuário Admin '{ADMIN_EMAIL}' já existe no Firebase Auth e Firestore.")

    except auth.UserNotFoundError:
        try:
            # Cria o usuário admin no Firebase Auth
            admin_auth_user = auth.create_user(
                email=ADMIN_EMAIL,
                password=ADMIN_PASSWORD,
                display_name="Admin ViqueiBET" # Updated display name
            )
            # Cria o perfil de usuário correspondente no Firestore
            admin_user = User(admin_auth_user.uid, ADMIN_EMAIL, is_admin=True)
            admin_user.save()
            print(f"Usuário Admin '{ADMIN_EMAIL}' criado no Firebase Auth e Firestore com UID {admin_auth_user.uid}.")
        except Exception as e:
            print(f"Erro ao criar usuário Admin no Firebase Auth: {e}")
else:
    # Se Firebase não inicializado, pré-registra admin na memória e salva no JSON
    if ADMIN_EMAIL not in _memory_users_db:
        admin_password_hash = generate_password_hash(ADMIN_PASSWORD, method='pbkdf2:sha256')
        _memory_users_db[ADMIN_EMAIL] = User(ADMIN_EMAIL, ADMIN_EMAIL, password_hash=admin_password_hash, is_admin=True)
        save_users_to_json(_memory_users_db) # Salva o admin recém-adicionado no JSON
        print(f"Usuário Admin '{ADMIN_EMAIL}' pré-registrado em memória e salvo em {USERS_JSON_FILE}.")


# --- Rota para a página de login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user_obj = None
        if firebase_initialized:
            try:
                # Se for o admin hardcoded, verifica a senha hardcoded
                if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
                    auth_user = auth.get_user_by_email(email)
                    user_obj = User.get(auth_user.uid)
                else: # Para outros usuários ou admin com senha Firebase Auth
                    try:
                        # Em um app real, a autenticação do Firebase seria feita no frontend
                        # usando a SDK JS do Firebase Auth. No backend, você verificaria o token de ID.
                        # Para esta simulação, estamos tratando o login como se fosse uma verificação direta.
                        auth_user = auth.get_user_by_email(email) # Tenta obter o usuário pelo email
                        # Se a senha não é do admin hardcoded, ela precisa ser verificada
                        # por um serviço de autenticação real ou um hash armazenado.
                        # Como estamos em um exemplo de backend, a autenticação via auth.get_user_by_email
                        # não verifica a senha. A verificação da senha precisa ser feita separadamente
                        # ou através de um processo de sign-in de cliente que retorne um token.
                        # Para este propósito, vamos tratar o login do admin como hardcoded e outros como base de dados.
                        # **AVISO**: Isso NÃO é uma implementação de autenticação segura para produção.
                        
                        # Simulação de verificação de senha para usuários não-admin no Firebase (se houver uma maneira de obter a senha)
                        # Como não podemos obter a senha no Firebase Admin SDK, este bloco é apenas um placeholder.
                        # A validação real viria do frontend com um token de ID do Firebase Auth.
                        user_obj = User.get(auth_user.uid) # Pega o perfil Firestore
                        if user_obj:
                            # Se for o admin, a senha já foi verificada pelo if acima.
                            # Para usuários normais, a senha precisa ser verificada no frontend via Firebase Auth.
                            pass # Assume que o Firebase Auth já verificou no cliente, ou a senha é hardcoded para admin.
                        else:
                            flash('E-mail não registrado.', 'danger')
                            return render_template('login.html', email=email)

                    except auth.UserNotFoundError:
                        flash('E-mail não registrado.', 'danger')
                        return render_template('login.html', email=email)
                    except Exception as e:
                        print(f"Erro durante a busca de usuário no Firebase Auth: {e}")
                        flash('Ocorreu um erro ao tentar logar. Tente novamente.', 'danger')
                        return render_template('login.html', email=email)

            except Exception as e:
                flash(f'Erro durante o login com Firebase: {e}', 'danger')
                return render_template('login.html', email=email)
        else: # Modo de memória/JSON
            user_obj = User.get(email) # Pega o usuário da memória pelo email
            if user_obj and check_password_hash(user_obj.password_hash, password):
                pass # Login bem-sucedido em memória
            else:
                flash('E-mail ou senha inválidos.', 'danger')
                return render_template('login.html', email=email)
        
        # Check if the user is banned AFTER authentication
        if user_obj and user_obj.is_banned:
            flash('Sua conta foi banida. Entre em contato com o suporte.', 'danger')
            return render_template('login.html', email=email)

        if user_obj:
            login_user(user_obj)
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Erro desconhecido ao processar login. Tente novamente.', 'danger')
            return render_template('login.html', email=email)

    return render_template('login.html')

# --- Rota para a página de registro ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        card_number = request.form.get('card_number')
        cpf_cnpj = request.form.get('cpf_cnpj')

        if firebase_initialized:
            try:
                auth.get_user_by_email(email)
                flash('E-mail já registrado. Por favor, faça login.', 'warning')
                return render_template('register.html', email=email, card_number=card_number, cpf_cnpj=cpf_cnpj)
            except auth.UserNotFoundError:
                pass # Usuário não existe, prosseguir com a criação
            except Exception as e:
                flash(f'Erro ao verificar e-mail no Firebase: {e}', 'danger')
                return render_template('register.html', email=email, card_number=card_number, cpf_cnpj=cpf_cnpj)

            try:
                # Cria usuário no Firebase Auth
                new_auth_user = auth.create_user(
                    email=email,
                    password=password,
                    display_name=email.split('@')[0] # Nome de exibição simples
                )

                # Armazena informações adicionais do usuário no Firestore
                new_user = User(new_auth_user.uid, email)
                
                # Armazena dados de pagamento/ID (opcional)
                if card_number:
                    new_user.card_info = {
                        "last_4": card_number[-4:],
                        "masked_full": f"XXXX XXXX XXXX {card_number[-4:]}"
                    }
                if cpf_cnpj:
                    new_user.personal_id = {
                        "type": "CPF/CNPJ",
                        "masked_value": f"XXX.XXX.XXX-{cpf_cnpj[-2:]}" if len(cpf_cnpj) >= 2 else cpf_cnpj
                    }
                
                new_user.save() # Salva no Firestore

                print(f"Novo Usuário Registrado (Firebase): Email={email}, Saldo={new_user.balance:.2f}")

                login_user(new_user)
                flash('Sua conta foi criada e você foi logado com sucesso!', 'success')
                return redirect(url_for('index'))

            except Exception as e:
                flash(f'Erro ao registrar com Firebase: {e}', 'danger')
                return render_template('register.html', email=email, card_number=card_number, cpf_cnpj=cpf_cnpj)
        else: # Modo de memória/JSON
            if email in _memory_users_db:
                flash('E-mail já registrado. Por favor, faça login.', 'warning')
                return render_template('register.html', email=email, card_number=card_number, cpf_cnpj=cpf_cnpj)
            
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(email, email, password_hash=hashed_password) # UID é o email para memória

            if card_number:
                new_user.card_info = {
                    "last_4": card_number[-4:],
                    "masked_full": f"XXXX XXXX XXXX {card_number[-4:]}"
                }
            if cpf_cnpj:
                new_user.personal_id = {
                    "type": "CPF/CNPJ",
                    "masked_value": f"XXX.XXX.XXX-{cpf_cnpj[-2:]}" if len(cpf_cnpj) >= 2 else cpf_cnpj
                }
            new_user.save() # Salva na memória e no JSON

            print(f"Novo Usuário Registrado (Memória): Email={email}, Saldo={new_user.balance:.2f}")

            login_user(new_user)
            flash('Sua conta foi criada e você foi logado com sucesso!', 'success')
            return redirect(url_for('index'))
    
    return render_template('register.html')

# --- Rota de Logout ---
@app.route('/logout')
@login_required # Garante que só usuários logados podem fazer logout
def logout():
    logout_user()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('login'))

# --- Rotas de Jogo e Finanças (Atualizadas para usar current_user e persistência) ---

@app.route('/')
@login_required
def index():
    return render_template('index.html', saldo=f"{current_user.balance:.2f}")

@app.route('/slots')
@login_required
def slots():
    return render_template('slots.html', saldo=f"{current_user.balance:.2f}")

@app.route('/roulette')
@login_required
def roulette():
    return render_template('roulette.html', saldo=f"{current_user.balance:.2f}")

@app.route('/auto_roulette') # Nova rota para a auto-roleta
@login_required
def auto_roulette():
    return render_template('auto_roulette.html', saldo=f"{current_user.balance:.2f}")

@app.route('/mines') # Nova rota para o Campo Minado
@login_required
def mines():
    return render_template('mines.html', saldo=f"{current_user.balance:.2f}")

@app.route('/crash') # Nova rota para o Crash
@login_required
def crash():
    return render_template('crash.html', saldo=f"{current_user.balance:.2f}")

@app.route('/fishing') # Nova rota para o Jogo de Pesca
@login_required
def fishing():
    return render_template('fishing.html', saldo=f"{current_user.balance:.2f}")

@app.route('/volcano') # Nova rota para o Jogo do Vulcão
@login_required
def volcano():
    return render_template('volcano.html', saldo=f"{current_user.balance:.2f}")

@app.route('/deposit', methods=['GET'])
@login_required
def deposit_page():
    return render_template('deposit.html', saldo=f"{current_user.balance:.2f}", user_email=current_user.email)

@app.route('/api/deposit', methods=['POST'])
@login_required
def api_deposit():
    # Esta API não é mais usada para o depósito real com o código.
    # Pode ser removida ou adaptada se houver outros tipos de depósito.
    # Por agora, mantenho-a para compatibilidade, mas a nova rota é api/redeem_deposit_code
    current_balance = current_user.balance
    data = request.get_json()
    deposit_amount = float(data.get('valor', 0.0))
    
    time.sleep(random.uniform(1.5, 3.0)) 

    # Simulated success/failure of deposit
    if random.random() < 0.5: # 50% chance de "falha"
        message = "Ocorreu um erro na transação. Seu depósito não foi processado. Por favor, tente novamente."
        status = "negado"
    else:
        current_user.balance += deposit_amount
        current_user.save() # Salva o saldo atualizado
        message = f"Depósito de R$ {deposit_amount:.2f} processado com sucesso! Seu novo saldo é R$ {current_user.balance:.2f}."
        status = "sucesso"
    
    print(f"Depósito de {current_user.email}: Valor={deposit_amount:.2f}, Status={status}. Saldo atual: {current_user.balance:.2f}")

    return jsonify({
        "message": message,
        "status": status,
        "saldo": f"{current_user.balance:.2f}"
    })

@app.route('/api/redeem_deposit_code', methods=['POST'])
@login_required
def api_redeem_deposit_code():
    data = request.get_json()
    code = data.get('code')

    if not code:
        return jsonify({"status": "error", "message": "Código de depósito não fornecido."}), 400

    deposit_code_data = None
    deposit_code_doc_ref = None

    if firebase_initialized:
        try:
            deposit_code_doc_ref = db.collection('artifacts').document(app_id).collection('public').document('data').collection('deposit_codes').document(code)
            doc = deposit_code_doc_ref.get()
            if doc.exists:
                deposit_code_data = doc.to_dict()
        except Exception as e:
            print(f"Erro ao buscar código de depósito no Firestore: {e}")
            return jsonify({"status": "error", "message": "Erro interno ao verificar o código."}), 500
    else:
        deposit_code_data = _memory_deposit_codes_db.get(code)
    
    if not deposit_code_data:
        return jsonify({"status": "error", "message": "Código de depósito inválido ou não encontrado."}), 404
    
    if deposit_code_data.get('is_used'):
        return jsonify({"status": "error", "message": "Código de depósito já foi utilizado."}), 400

    deposit_amount = deposit_code_data.get('amount', 0.0)
    current_user.balance += float(deposit_amount)

    # Marcar código como usado
    if firebase_initialized:
        try:
            deposit_code_doc_ref.update({
                'is_used': True,
                'used_by': current_user.email,
                'used_at': datetime.now().isoformat()
            })
        except Exception as e:
            print(f"Erro ao marcar código como usado no Firestore: {e}")
            # Tentar reverter o saldo se o update falhar (para consistência)
            current_user.balance -= float(deposit_amount)
            current_user.save()
            return jsonify({"status": "error", "message": "Erro ao resgatar o código. Tente novamente."}), 500
    else:
        _memory_deposit_codes_db[code]['is_used'] = True
        _memory_deposit_codes_db[code]['used_by'] = current_user.email
        _memory_deposit_codes_db[code]['used_at'] = datetime.now().isoformat()
        save_deposit_codes_to_json(_memory_deposit_codes_db)

    current_user.save()
    print(f"Código de depósito {code} resgatado por {current_user.email}. Valor: {deposit_amount:.2f}. Saldo atual: {current_user.balance:.2f}")
    
    return jsonify({
        "status": "success",
        "message": f"Código resgatado com sucesso! R$ {deposit_amount:.2f} adicionados ao seu saldo.",
        "saldo": f"{current_user.balance:.2f}"
    })


@app.route('/api/spin', methods=['POST'])
@login_required
def api_spin():
    current_balance = current_user.balance
    data = request.get_json()
    bet_amount = float(data.get('aposta', 10.0))

    if current_balance < bet_amount:
        return jsonify({"message": "Saldo insuficiente!", "saldo": f"{current_balance:.2f}", "resultado": ["-", "-", "-"]}), 400

    old_balance = current_balance
    current_user.balance -= bet_amount

    # Lógica para forçar resultado de Slots
    forced_setting = current_user.forced_game_outcome
    is_forced_game = False
    if forced_setting['game_type'] == 'slots' and forced_setting['outcome'] is not None:
        is_forced_game = True
        forced_outcome_type = forced_setting['outcome']
        # A configuração PERSISTE até ser desativada pelo admin

    simbolos = ['🍒', '🍋', '🔔', '💰', '⭐']
    resultado_rolos = []
    winnings = 0.0
    message = "Você perdeu!"
    outcome = "lost"

    if is_forced_game:
        if forced_outcome_type == 'win':
            # Força um resultado de vitória com um grande ganho
            resultado_rolos = ['⭐', '⭐', '⭐']
            winnings = bet_amount * 20.0 # GANHO BEM MAIOR
            message = "JACKPOT! Você ganhou MUITO dinheiro! Sua sorte é inacreditável!"
            outcome = "forced_win"
        else: # forçar derrota
            # Força um resultado de derrota
            resultado_rolos = ['🍒', '🍋', '🔔'] # Todos diferentes
            winnings = 0.0
            message = "Você perdeu. Tente novamente!"
            outcome = "forced_loss"
    else:
        # Lógica original de sorteio aleatório (com alta chance de perda)
        resultado_rolos = [random.choice(simbolos) for _ in range(3)]
        if resultado_rolos[0] == resultado_rolos[1] == resultado_rolos[2]:
            if resultado_rolos[0] == '🍒':
                winnings = bet_amount * 0.5
                message = "Você ganhou um pouco!"
                outcome = "partial_win"
            elif resultado_rolos[0] == '🍋':
                winnings = bet_amount * 0.8
                message = "Quase lá!"
                outcome = "partial_win"
            else:
                winnings = bet_amount * 1.2
                message = "Vitória RARA! Continue jogando!"
                outcome = "rare_win"
        elif resultado_rolos[0] == resultado_rolos[1] or resultado_rolos[1] == resultado_rolos[2]:
            winnings = bet_amount * 0.1
            message = "Você quase ganhou! Tente de novo!"
            outcome = "minor_win"

    current_user.balance += winnings

    # Lógica de ajuste de golpe (aplica-se APENAS se o jogo NÃO foi forçado)
    if not is_forced_game and current_user.balance > old_balance and winnings > 0:
        if current_user.balance - old_balance > bet_amount * 0.5:
            current_user.balance = old_balance - bet_amount * 0.2
            message += " (Ajuste de saldo: sistema instável)" 
            outcome = "adjusted_loss" 
    
    current_user.save()

    print(f"Slots de {current_user.email}: Aposta={bet_amount}, Saldo Anterior={old_balance:.2f}, Resultado={resultado_rolos}, Ganho={winnings:.2f}, Saldo Atual={current_user.balance:.2f}")

    return jsonify({
        "message": message,
        "saldo": f"{current_user.balance:.2f}",
        "resultado": resultado_rolos,
        "ganho": f"{winnings:.2f}"
    })

@app.route('/api/roll', methods=['POST'])
@login_required
def api_roll():
    current_balance = current_user.balance
    data = request.get_json()
    bet_amount = float(data.get('aposta_valor', 10.0))
    bet_type = data.get('aposta_tipo', 'vermelho')

    if current_balance < bet_amount:
        return jsonify({"message": "Saldo insuficiente!", "saldo": f"{current_balance:.2f}", "numero_sorteado": -1}), 400

    old_balance = current_balance
    current_user.balance -= bet_amount

    # Lógica para forçar resultado de Roleta
    forced_setting = current_user.forced_game_outcome
    is_forced_game = False
    if forced_setting['game_type'] == 'roulette' and forced_setting['outcome'] is not None:
        is_forced_game = True
        forced_outcome_type = forced_setting['outcome']
        # A configuração PERSISTE até ser desativada pelo admin

    numeros = list(range(37))
    cores = {
        0: 'verde', 1: 'vermelho', 2: 'preto', 3: 'vermelho', 4: 'preto', 5: 'vermelho', 6: 'preto',
        7: 'vermelho', 8: 'preto', 9: 'vermelho', 10: 'preto', 11: 'preto', 12: 'vermelho',
        13: 'preto', 14: 'vermelho', 15: 'preto', 16: 'vermelho', 17: 'preto', 18: 'vermelho',
        19: 'vermelho', 20: 'preto', 21: 'vermelho', 22: 'preto', 23: 'vermelho', 24: 'preto',
        25: 'vermelho', 26: 'preto', 27: 'vermelho', 28: 'preto', 29: 'preto', 30: 'vermelho',
        31: 'preto', 32: 'vermelho', 33: 'preto', 34: 'vermelho', 35: 'preto', 36: 'vermelho',
    }

    numero_sorteado = -1
    cor_sorteada = "desconhecido"
    winnings = 0.0
    message = "Você perdeu!"
    outcome = "lost"

    if is_forced_game:
        if forced_outcome_type == 'win':
            # Tenta forçar uma vitória baseada nos tipos de aposta comuns com grandes ganhos
            if bet_type == 'vermelho':
                winning_numbers = [n for n in numeros if cores.get(n) == 'vermelho']
                numero_sorteado = random.choice(winning_numbers) if winning_numbers else 1 # Fallback
                cor_sorteada = cores.get(numero_sorteado, 'vermelho')
                winnings = bet_amount * 5.0 # Bom ganho para cor
                message = f"EXPLOSÃO DE COR! A cor {cor_sorteada.upper()} te deu um baita lucro! Continue jogando!"
            elif bet_type == 'preto':
                winning_numbers = [n for n in numeros if cores.get(n) == 'preto']
                numero_sorteado = random.choice(winning_numbers) if winning_numbers else 2 # Fallback
                cor_sorteada = cores.get(numero_sorteado, 'preto')
                winnings = bet_amount * 5.0 # Bom ganho para cor
                message = f"EXPLOSÃO DE COR! A cor {cor_sorteada.upper()} te deu um baita lucro! Continue jogando!"
            elif bet_type == 'numero':
                try:
                    num_apostado = int(data.get('numero_apostado'))
                    if 0 <= num_apostado <= 36:
                        numero_sorteado = num_apostado
                    else: # Fallback se um número inválido foi fornecido para força de vitória
                        numero_sorteado = random.choice(numeros) # Default aleatório
                except (ValueError, TypeError):
                    numero_sorteado = random.choice(numeros) # Default aleatório
                
                cor_sorteada = cores.get(numero_sorteado, 'desconhecido')
                winnings = bet_amount * 35.0 # Altíssimo pagamento para número
                message = f"APOSTA LENDÁRIA! O número {numero_sorteado} é o seu amuleto da sorte! Você acabou de fazer uma fortuna!"
            else: # Ganho genérico se as condições específicas não forem atendidas ou tipo de aposta estranho
                numero_sorteado = random.choice(numeros)
                cor_sorteada = cores.get(numero_sorteado, 'desconhecido')
                winnings = bet_amount * 3.0
                message = "Você ganhou um pouco! Tente novamente!"
            outcome = "forced_win"

        else: # forçar derrota
            # Força um resultado de derrota
            if bet_type == 'vermelho':
                losing_numbers = [n for n in numeros if cores.get(n) in ['preto', 'verde']]
                numero_sorteado = random.choice(losing_numbers) if losing_numbers else 0
            elif bet_type == 'preto':
                losing_numbers = [n for n in numeros if cores.get(n) in ['vermelho', 'verde']]
                numero_sorteado = random.choice(losing_numbers) if losing_numbers else 0
            elif bet_type == 'numero':
                num_apostado = int(data.get('numero_apostado', -1))
                possible_losing_numbers = [n for n in numeros if n != num_apostado]
                numero_sorteado = random.choice(possible_losing_numbers) if possible_losing_numbers else (0 if num_apostado != 0 else 1)
            else:
                numero_sorteado = 0 # Padrão para zero para perda genérica

            cor_sorteada = cores.get(numero_sorteado, 'desconhecido')
            winnings = 0.0
            message = "Você perdeu. A casa sempre ganha."
            outcome = "forced_loss"
    else:
        # Lógica original de sorteio aleatório (com alta chance de perda)
        numero_sorteado = random.choice(numeros)
        cor_sorteada = cores.get(numero_sorteado, 'desconhecido')

        if bet_type == 'vermelho' and cor_sorteada == 'vermelho':
            winnings = bet_amount * 0.5
            message = "Quase lá no vermelho! Tente mais!"
            outcome = "partial_win_color"
        elif bet_type == 'preto' and cor_sorteada == 'preto':
            winnings = bet_amount * 0.5
            message = "Quase lá no preto! Tente mais!"
            outcome = "partial_win_color"
        elif bet_type == 'numero' and str(numero_sorteado) == data.get('numero_apostado'):
            winnings = bet_amount * 5
            message = f"Vitória RARA no número {numero_sorteado}! Continue apostando!"
            outcome = "rare_win_number"
        elif numero_sorteado == 0:
            message = "Caiu no zero... a casa sempre ganha!"
            outcome = "zero_loss"

    current_user.balance += winnings

    # Lógica de ajuste de golpe (aplica-se APENAS se o jogo NÃO foi forçado)
    if not is_forced_game and current_user.balance > old_balance and winnings > 0:
        if current_user.balance - old_balance > bet_amount * 0.8:
            current_user.balance = old_balance - bet_amount * 0.3
            message += " (Ajuste de saldo: sistema instável)"
            outcome = "adjusted_loss"

    current_user.save()

    print(f"Roleta de {current_user.email}: Aposta Valor={bet_amount}, Tipo={bet_type}, Saldo Anterior={old_balance:.2f}, Sorteado={numero_sorteado} ({cor_sorteada}), Ganho={winnings:.2f}, Saldo Atual={current_user.balance:.2f}")

    return jsonify({
        "message": message,
        "saldo": f"{current_user.balance:.2f}",
        "numero_sorteado": numero_sorteado,
        "cor_sorteada": cor_sorteada,
        "ganho": f"{winnings:.2f}"
    })

@app.route('/api/mines/start_game', methods=['POST'])
@login_required
def api_mines_start_game():
    data = request.get_json()
    bet_amount = float(data.get('bet_amount', 10.0))
    mines_count = int(data.get('mines_count', 3)) # Number of mines

    if current_user.balance < bet_amount:
        return jsonify({"status": "error", "message": "Saldo insuficiente para iniciar o jogo!"}), 400

    if not (1 <= mines_count <= 24): # Max 24 mines on a 5x5 board (25 tiles)
        return jsonify({"status": "error", "message": "Número de minas inválido (1-24)."}), 400

    current_user.balance -= bet_amount
    current_user.save()

    # Game state for Mines (client-side, but mines must be set on server)
    board_size = 5 * 5 # 5x5 board
    
    # Place mines randomly
    all_tiles = list(range(board_size))
    mine_positions = random.sample(all_tiles, mines_count)
    
    # Store initial game state in session for tracking during clicks
    session['mines_game_state'] = {
        'bet_amount': bet_amount,
        'mines_count': mines_count,
        'mine_positions': mine_positions,
        'revealed_tiles': [],
        'current_multiplier': 1.0,
        'is_active': True,
        'initial_balance': current_user.balance + bet_amount # Store for logging if needed
    }

    print(f"Mines de {current_user.email}: Jogo iniciado. Aposta={bet_amount}, Minas={mines_count}. Saldo atual: {current_user.balance:.2f}")

    return jsonify({
        "status": "success",
        "message": "Jogo Campo Minado iniciado!",
        "saldo": f"{current_user.balance:.2f}",
        "board_size": board_size
    })

@app.route('/api/mines/reveal_tile', methods=['POST'])
@login_required
def api_mines_reveal_tile():
    data = request.get_json()
    tile_index = int(data.get('tile_index'))

    game_state = session.get('mines_game_state')
    if not game_state or not game_state['is_active']:
        return jsonify({"status": "error", "message": "Nenhum jogo ativo de Campo Minado. Por favor, inicie um novo jogo."}), 400

    if tile_index in game_state['revealed_tiles']:
        return jsonify({"status": "error", "message": "Este tile já foi revelado."}), 400

    forced_setting = current_user.forced_game_outcome
    is_forced_game = (forced_setting['game_type'] == 'mines' and forced_setting['outcome'] is not None)
    forced_outcome_type = forced_setting['outcome'] if is_forced_game else None

    revealed_tiles = game_state['revealed_tiles']
    mine_positions = game_state['mine_positions']
    current_multiplier = game_state['current_multiplier']
    bet_amount = game_state['bet_amount']

    message = ""
    status = "continue"
    won_amount = 0.0

    # Lógica de forçar resultado
    if is_forced_game:
        if forced_outcome_type == 'win':
            # Se forçar vitória, este tile não pode ser uma mina
            if tile_index in mine_positions:
                # Se o usuário clicou numa mina, finge que não era uma mina para forçar vitória.
                # Remove esta mina das posições de mina e adiciona uma nova em outro lugar.
                mine_positions.remove(tile_index)
                safe_tiles_count = 25 - len(mine_positions) - len(revealed_tiles)
                if safe_tiles_count > 0:
                    new_mine_pos = random.choice([t for t in range(25) if t not in mine_positions and t != tile_index and t not in revealed_tiles])
                    mine_positions.append(new_mine_pos)
                print(f"MINES SCAM: Mine at {tile_index} avoided. Moved it elsewhere.")
            
            current_multiplier += random.uniform(0.5, 1.5) # Aumento garantido
            message = f"Incrível! Multiplicador subiu para x{current_multiplier:.2f}!"
            revealed_tiles.append(tile_index)
        elif forced_outcome_type == 'lose':
            # Se forçar derrota, este tile DEVE ser uma mina
            if tile_index not in mine_positions:
                # Se o usuário clicou num tile seguro, transforma ele numa mina (scam!)
                # Remove uma mina aleatória das minas existentes para manter a contagem
                if mine_positions:
                    mine_positions.remove(random.choice(mine_positions))
                mine_positions.append(tile_index)
                print(f"MINES SCAM: Forced mine at {tile_index}.")

            status = "exploded"
            message = "BOOM! Você clicou em uma mina. Fim de jogo!"
            game_state['is_active'] = False
    elif tile_index in mine_positions: # Jogo normal, clicou numa mina
        status = "exploded"
        message = "BOOM! Você clicou em uma mina. Fim de jogo!"
        game_state['is_active'] = False
    else: # Jogo normal, tile seguro
        revealed_tiles.append(tile_index)
        current_multiplier += random.uniform(0.1, 0.4) # Aumento realista
        message = f"Tile seguro! Multiplicador atual: x{current_multiplier:.2f}"

    won_amount = bet_amount * current_multiplier # Multiplicador atual, potencial

    game_state['revealed_tiles'] = revealed_tiles
    game_state['current_multiplier'] = current_multiplier
    game_state['mine_positions'] = mine_positions # Atualiza se houver manipulação
    session['mines_game_state'] = game_state # Update session state

    print(f"Mines de {current_user.email}: Tile {tile_index}, Status={status}, Multiplicador={current_multiplier:.2f}, Saldo Atual={current_user.balance:.2f}")

    return jsonify({
        "status": status,
        "message": message,
        "saldo": f"{current_user.balance:.2f}",
        "current_multiplier": f"{current_multiplier:.2f}",
        "won_amount": f"{won_amount:.2f}", # Only really relevant on cashout/loss
        "mine_positions": mine_positions if status == "exploded" else [] # Reveal mines on loss
    })


@app.route('/api/mines/cash_out', methods=['POST'])
@login_required
def api_mines_cash_out():
    game_state = session.get('mines_game_state')
    if not game_state or not game_state['is_active']:
        return jsonify({"status": "error", "message": "Nenhum jogo ativo de Campo Minado para sacar."}), 400

    bet_amount = game_state['bet_amount']
    current_multiplier = game_state['current_multiplier']
    
    won_amount = bet_amount * current_multiplier
    current_user.balance += won_amount
    current_user.save()

    session['mines_game_state']['is_active'] = False # End the game

    message = f"Você sacou! Ganhou R$ {won_amount:.2f} com um multiplicador de x{current_multiplier:.2f}!"
    status = "cashed_out"

    print(f"Mines de {current_user.email}: Sacou R$ {won_amount:.2f} (x{current_multiplier:.2f}). Saldo final: {current_user.balance:.2f}")

    return jsonify({
        "status": status,
        "message": message,
        "saldo": f"{current_user.balance:.2f}",
        "won_amount": f"{won_amount:.2f}",
        "mine_positions": game_state['mine_positions'] # Reveal mines on cashout
    })


@app.route('/api/crash/start_game', methods=['POST'])
@login_required
def api_crash_start_game():
    data = request.get_json()
    bet_amount = float(data.get('bet_amount', 10.0))
    speed_factor = float(data.get('speed_factor', 1.0)) # Novo: fator de velocidade

    if current_user.balance < bet_amount:
        return jsonify({"status": "error", "message": "Saldo insuficiente para iniciar o jogo!"}), 400

    current_user.balance -= bet_amount
    current_user.save()

    # Determine crash point
    crash_point = 1.0 + (random.random() ** 2) * 99.0 # More likely to crash early, but can go high
    
    # Apply forced outcome
    forced_setting = current_user.forced_game_outcome
    is_forced_game = (forced_setting['game_type'] == 'crash' and forced_setting['outcome'] is not None)
    
    if is_forced_game:
        if forced_setting['outcome'] == 'win':
            crash_point = 100.0 + random.uniform(10.0, 50.0) # Very high crash point for guaranteed win
            print(f"Crash forced win: Crash point set to {crash_point:.2f}")
        elif forced_setting['outcome'] == 'lose':
            crash_point = 1.0 + random.uniform(0.01, 0.1) # Crash almost immediately
            print(f"Crash forced lose: Crash point point set to {crash_point:.2f}")

    session['crash_game_state'] = {
        'bet_amount': bet_amount,
        'crash_point': crash_point,
        'current_multiplier': 1.0,
        'is_crashed': False,
        'is_active': True,
        'has_cashed_out': False,
        'speed_factor': speed_factor # Salva o fator de velocidade
    }

    print(f"Crash de {current_user.email}: Jogo iniciado. Aposta={bet_amount}, Crash Point={crash_point:.2f}, Velocidade={speed_factor}. Saldo atual: {current_user.balance:.2f}")

    return jsonify({
        "status": "success",
        "message": "Jogo Crash iniciado!",
        "saldo": f"{current_user.balance:.2f}",
        "crash_point": f"{crash_point:.2f}"
    })

@app.route('/api/crash/update_multiplier', methods=['POST'])
@login_required
def api_crash_update_multiplier():
    game_state = session.get('crash_game_state')
    if not game_state or not game_state['is_active'] or game_state['is_crashed']:
        return jsonify({"status": "error", "message": "Nenhum jogo ativo de Crash ou já caiu."}), 400

    speed_factor = game_state.get('speed_factor', 1.0)
    increment_factor = random.uniform(0.01, 0.05) * speed_factor # Ajusta o incremento pela velocidade
    new_multiplier = game_state['current_multiplier'] + increment_factor

    if new_multiplier >= game_state['crash_point']:
        new_multiplier = game_state['crash_point']
        game_state['is_crashed'] = True
        game_state['is_active'] = False
        message = f"CRASH! O jogo caiu em x{new_multiplier:.2f}."
        status = "crashed"
    else:
        message = "Multiplicador aumentando..."
        status = "running"

    game_state['current_multiplier'] = new_multiplier
    session['crash_game_state'] = game_state

    return jsonify({
        "status": status,
        "message": message,
        "current_multiplier": f"{new_multiplier:.2f}",
        "is_crashed": game_state['is_crashed'],
        "saldo": f"{current_user.balance:.2f}" # Saldo não muda até o cashout
    })

@app.route('/api/crash/cash_out', methods=['POST'])
@login_required
def api_crash_cash_out():
    game_state = session.get('crash_game_state')
    if not game_state or not game_state['is_active'] or game_state['is_crashed'] or game_state['has_cashed_out']:
        return jsonify({"status": "error", "message": "Nenhum jogo Crash ativo para sacar ou já sacou/caiu."}), 400

    bet_amount = game_state['bet_amount']
    cashed_out_multiplier = game_state['current_multiplier']
    
    won_amount = bet_amount * cashed_out_multiplier
    current_user.balance += won_amount
    current_user.save()

    game_state['has_cashed_out'] = True
    game_state['is_active'] = False # End the game
    session['crash_game_state'] = game_state # Update session

    message = f"Você sacou! Ganhou R$ {won_amount:.2f} com um multiplicador de x{cashed_out_multiplier:.2f}!"
    status = "cashed_out"

    print(f"Crash de {current_user.email}: Sacou R$ {won_amount:.2f} (x{cashed_out_multiplier:.2f}). Saldo final: {current_user.balance:.2f}")

    return jsonify({
        "status": status,
        "message": message,
        "saldo": f"{current_user.balance:.2f}",
        "won_amount": f"{won_amount:.2f}",
        "cashed_out_multiplier": f"{cashed_out_multiplier:.2f}"
    })


@app.route('/api/fishing_game', methods=['POST'])
@login_required
def api_fishing_game():
    data = request.get_json()
    bet_amount = float(data.get('aposta', 5.0))

    if current_user.balance < bet_amount:
        return jsonify({"message": "Saldo insuficiente!", "saldo": f"{current_user.balance:.2f}", "resultado": "Sem sorte"}), 400

    old_balance = current_user.balance
    current_user.balance -= bet_amount

    forced_setting = current_user.forced_game_outcome
    is_forced_game = (forced_setting['game_type'] == 'fishing' and forced_setting['outcome'] is not None)
    forced_outcome_type = forced_setting['outcome'] if is_forced_game else None

    result_message = "Você jogou a isca... mas nada mordeu."
    winnings = 0.0
    outcome_type = "lost"

    if is_forced_game:
        if forced_outcome_type == 'win':
            fish_type = random.choice(['🐠 Peixe Dourado (Raro)', '🐳 Baleia da Sorte (Lendário)'])
            if 'Dourado' in fish_type:
                winnings = bet_amount * random.uniform(5.0, 10.0)
            else:
                winnings = bet_amount * random.uniform(15.0, 30.0)
            result_message = f"🏆 Você pegou um {fish_type}! GANHOS ENORMES!"
            outcome_type = "forced_win"
        else: # force lose
            result_message = "🐠 Sua isca afundou. Tente outra vez."
            winnings = 0.0
            outcome_type = "forced_loss"
    else:
        # Probabilidades de um casino scam: alta chance de perder, pequena chance de pequenos ganhos, raríssima chance de grande ganho.
        rand_num = random.random()
        if rand_num < 0.70: # 70% chance de perder
            result_message = "🐟 Nada. A água está vazia. Tente de novo!"
            winnings = 0.0
        elif rand_num < 0.90: # 20% chance de pequeno ganho
            fish_type = random.choice(['Minhoca (pequeno)', 'Caranguejo (pequeno)'])
            winnings = bet_amount * random.uniform(0.1, 0.3)
            result_message = f"🎣 Pegou um {fish_type}! Pequeno ganho."
        elif rand_num < 0.98: # 8% chance de ganho médio
            fish_type = random.choice(['Tubarão (médio)', 'Salmão (médio)'])
            winnings = bet_amount * random.uniform(0.5, 1.5)
            result_message = f"🦈 Pesca boa! Pegou um {fish_type}! Você está com sorte!"
        else: # 2% chance de grande ganho (raro)
            fish_type = random.choice(['🐠 Peixe Dourado (Raro)', '🐳 Baleia da Sorte (Lendário)'])
            winnings = bet_amount * random.uniform(3.0, 10.0)
            result_message = f"🌟 UAU! Você pegou um {fish_type}! MEGA GANHO!"
        outcome_type = "random"

    current_user.balance += winnings
    current_user.save()

    print(f"Pesca de {current_user.email}: Aposta={bet_amount}, Saldo Anterior={old_balance:.2f}, Mensagem='{result_message}', Ganho={winnings:.2f}, Saldo Atual={current_user.balance:.2f}")

    return jsonify({
        "message": result_message,
        "saldo": f"{current_user.balance:.2f}",
        "ganho": f"{winnings:.2f}",
        "outcome_type": outcome_type
    })


@app.route('/api/volcano_game', methods=['POST'])
@login_required
def api_volcano_game():
    data = request.get_json()
    bet_amount = float(data.get('aposta', 10.0))
    # 'bet_multiplier' é o multiplicador que o usuário aposta que o vulcão vai atingir ou passar
    bet_multiplier = float(data.get('bet_multiplier', 2.0)) 

    if current_user.balance < bet_amount:
        return jsonify({"message": "Saldo insuficiente!", "saldo": f"{current_user.balance:.2f}", "result_multiplier": 1.0}), 400

    if not (1.1 <= bet_multiplier <= 10.0): # Exemplo de limites para aposta de multiplicador
        return jsonify({"message": "Multiplicador de aposta inválido! Escolha entre 1.1x e 10.0x."}), 400

    old_balance = current_user.balance
    current_user.balance -= bet_amount

    forced_setting = current_user.forced_game_outcome
    is_forced_game = (forced_setting['game_type'] == 'volcano' and forced_setting['outcome'] is not None)
    forced_outcome_type = forced_setting['outcome'] if is_forced_game else None

    result_multiplier = 1.0
    winnings = 0.0
    message = "O vulcão nem tremeu. Perdeu!"
    outcome_type = "lost"

    if is_forced_game:
        if forced_outcome_type == 'win':
            # Força o multiplicador do vulcão a ser maior que a aposta do usuário
            result_multiplier = bet_multiplier + random.uniform(0.1, 2.0) # Garante vitória
            winnings = bet_amount * result_multiplier
            message = f"🌋 ERUPÇÃO ÉPICA! Você acertou em cheio! Multiplicador x{result_multiplier:.2f}! Seus ganhos dispararam!"
            outcome_type = "forced_win"
        else: # force lose
            # Força o multiplicador do vulcão a ser menor que a aposta do usuário
            result_multiplier = random.uniform(1.0, bet_multiplier - 0.1) # Garante derrota
            if result_multiplier < 1.0: result_multiplier = 1.0 # Garante mínimo
            winnings = 0.0
            message = f"🔥 Que pena! O vulcão caiu em x{result_multiplier:.2f}. Você perdeu."
            outcome_type = "forced_loss"
    else:
        # Simulação aleatória de erupção
        # Grande chance de cair baixo, pequena chance de subir muito.
        rand_val = random.random()
        if rand_val < 0.60: # 60% de chance de cair entre 1.0x e 1.5x (perder a maioria das apostas)
            result_multiplier = random.uniform(1.0, 1.5)
        elif rand_val < 0.85: # 25% de chance de cair entre 1.5x e 3.0x
            result_multiplier = random.uniform(1.5, 3.0)
        elif rand_val < 0.95: # 10% de chance de cair entre 3.0x e 5.0x
            result_multiplier = random.uniform(3.0, 5.0)
        else: # 5% de chance de cair entre 5.0x e 15.0x (raro, mas possível)
            result_multiplier = random.uniform(5.0, 15.0)
        
        if result_multiplier >= bet_multiplier:
            winnings = bet_amount * result_multiplier
            message = f"🌋 ERUPÇÃO! O vulcão atingiu x{result_multiplier:.2f}! Você ganhou!"
            outcome_type = "won"
        else:
            winnings = 0.0
            message = f"🔥 Que pena! O vulcão caiu em x{result_multiplier:.2f}. Você perdeu."
            outcome_type = "lost"

    current_user.balance += winnings
    current_user.save()

    print(f"Vulcão de {current_user.email}: Aposta={bet_amount}, Aposta Multiplicador={bet_multiplier:.2f}, Resultado Multiplicador={result_multiplier:.2f}, Ganho={winnings:.2f}, Saldo Atual={current_user.balance:.2f}")

    return jsonify({
        "message": message,
        "saldo": f"{current_user.balance:.2f}",
        "ganho": f"{winnings:.2f}",
        "result_multiplier": f"{result_multiplier:.2f}",
        "outcome_type": outcome_type
    })


@app.route('/api/withdraw', methods=['POST'])
@login_required
def api_withdraw():
    current_balance = current_user.balance
    data = request.get_json()
    withdraw_amount = float(data.get('valor', 0.0))

    # Em um cassino "scam" real, os saques são frequentemente difíceis ou impossíveis.
    # Vamos simular um "erro de processamento" comum.
    message = "Erro no processamento do saque. Transação em análise. Por favor, entre em contato com o suporte ou tente novamente mais tarde."
    status = "em_analise" # Não é uma "falha" direta, mas um "padrão de retenção"

    current_user.save() # Salva o usuário (logs removidos)

    print(f"Tentativa de Saque de {current_user.email}: Valor={withdraw_amount}, Saldo Atual={current_balance:.2f}. Status: {status}.")

    return jsonify({
        "message": message,
        "status": status,
        "saldo": f"{current_user.balance:.2f}" # O saldo não muda em saque "pendente"
    })

# --- Dashboard Admin ---
def admin_required(f):
    """
    Decorador personalizado para garantir que apenas admins acessem a rota.
    """
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Acesso negado. Você não tem permissões de administrador.', 'danger')
            return redirect(url_for('index'))
        if current_user.is_banned: # Admins cannot access if they are banned
            flash('Sua conta foi banida e não pode acessar o painel de administração.', 'danger')
            logout_user() # Force logout if admin tries to access while banned
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__ 
    decorated_function.__qualname__ = f.__qualname__
    return decorated_function

from flask import Flask, request, jsonify, render_template, flash
from functools import wraps
import datetime

app = Flask(__name__)

# Configurações globais
MAINTENANCE_MODE = False
IMMUNE_USERS = ["lucasvtittontitton@gmail.com", "admin@voxelix.gg"]
ADMIN_EMAILS = ["admin@voxelix.gg"]  # Emails com acesso admin total

# Decorator para verificar admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.email not in ADMIN_EMAILS:
            flash('Acesso restrito a administradores', 'danger')
            return render_template('errors/403.html'), 403
        return f(*args, **kwargs)
    return decorated_function

# Middleware para verificar manutenção
@app.before_request
def check_maintenance():
    if MAINTENANCE_MODE and request.path not in ['/static', '/admin', '/admin/toggle_maintenance']:
        if not current_user.is_authenticated or current_user.email not in IMMUNE_USERS:
            return render_template('errors/500.html', 
                                message="Sistema em manutenção. Tente novamente mais tarde."), 500

# Rota para alternar manutenção
@app.route('/admin/toggle_maintenance', methods=['POST'])
@admin_required
def toggle_maintenance():
    global MAINTENANCE_MODE
    MAINTENANCE_MODE = not MAINTENANCE_MODE
    
    if firebase_initialized:
        try:
            maintenance_ref = db.collection('system_settings').document('maintenance')
            maintenance_ref.set({
                'active': MAINTENANCE_MODE,
                'updated_by': current_user.email,
                'updated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'immune_users': IMMUNE_USERS
            }, merge=True)
        except Exception as e:
            print(f"Erro ao atualizar status de manutenção: {e}")
            return jsonify({
                'status': 'error',
                'message': 'Erro ao salvar no banco de dados'
            }), 500
    
    return jsonify({
        'status': 'success',
        'message': f'Modo manutenção {"ativado" if MAINTENANCE_MODE else "desativado"}',
        'maintenance_mode': MAINTENANCE_MODE
    })

# Rota admin dashboard completa
@app.route('/admin', endpoint='admin_dashboard_view')
@admin_required
def admin_dashboard():
    # Carregar estado de manutenção do Firestore se disponível
    if firebase_initialized:
        try:
            maintenance_ref = db.collection('system_settings').document('maintenance')
            maintenance_data = maintenance_ref.get().to_dict()
            global MAINTENANCE_MODE
            MAINTENANCE_MODE = maintenance_data.get('active', False) if maintenance_data else False
        except Exception as e:
            print(f"Erro ao carregar status de manutenção: {e}")

    # Listar usuários
    all_users = []
    if firebase_initialized:
        try:
            users_in_auth = auth.list_users(max_results=1000).users
            for auth_user in users_in_auth:
                user_doc = db.collection('users').document(auth_user.uid).get()
                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    user_data['uid'] = auth_user.uid
                    user_data['email'] = auth_user.email
                    user_data['is_admin'] = auth_user.email in ADMIN_EMAILS
                    all_users.append(user_data)
        except Exception as e:
            print(f"Erro ao listar usuários: {e}")
            flash('Erro ao carregar usuários', 'danger')
    else:
        all_users = list(_memory_users_db.values())

    # Listar códigos de depósito
    deposit_codes = []
    if firebase_initialized:
        try:
            codes_ref = db.collection('deposit_codes').order_by('generated_at', direction='DESCENDING').limit(100)
            deposit_codes = [{'code': doc.id, **doc.to_dict()} for doc in codes_ref.stream()]
        except Exception as e:
            print(f"Erro ao listar códigos: {e}")
            flash('Erro ao carregar códigos', 'danger')
    else:
        deposit_codes = sorted(_memory_deposit_codes_db.values(), 
                             key=lambda x: x.get('generated_at', ''), 
                             reverse=True)

    return render_template(
        'admin.html',
        users=all_users,
        deposit_codes=deposit_codes,
        maintenance_mode=MAINTENANCE_MODE,
        current_user=current_user,
        immune_users=IMMUNE_USERS
    )

# Rota para atualizar status de usuário
@app.route('/admin/update_user_status', methods=['POST'])
@admin_required
def update_user_status():
    data = request.get_json()
    try:
        user_ref = db.collection('users').document(data['uid'])
        
        updates = {}
        if 'is_admin' in data:
            updates['is_admin'] = data['is_admin']
        if 'is_banned' in data:
            updates['is_banned'] = data['is_banned']
            # Atualizar no Auth também
            auth.update_user(data['uid'], disabled=data['is_banned'])
        
        user_ref.update(updates)
        return jsonify({'status': 'success'})
    except Exception as e:
        print(f"Erro ao atualizar usuário: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/admin/update_balance', methods=['POST'], endpoint='admin_update_balance_api')
@admin_required
def api_admin_update_balance():
    data = request.get_json()
    user_email = data.get('email')
    amount = float(data.get('amount'))
    action = data.get('action') # 'add' ou 'remove'

    target_user_uid_or_email = None
    if firebase_initialized:
        try:
            auth_user = auth.get_user_by_email(user_email)
            target_user_uid_or_email = auth_user.uid
        except auth.UserNotFoundError:
            return jsonify({"status": "error", "message": "Usuário não encontrado no Firebase Auth."}), 404
        except Exception as e:
            return jsonify({"status": "error", "message": f"Erro ao buscar usuário no Firebase Auth: {e}"}), 500
    else: # Modo de memória/JSON
        target_user_uid_or_email = user_email
    
    target_user = User.get(target_user_uid_or_email)
    if not target_user:
        return jsonify({"status": "error", "message": "Perfil de usuário não encontrado no banco de dados."}), 404

    old_balance = target_user.balance
    message = ""
    status = "error"

    if action == 'add':
        target_user.balance += amount
        message = f"Saldo de {user_email} adicionado em R$ {amount:.2f}. Novo saldo: R$ {target_user.balance:.2f}."
        status = "success"
    elif action == 'remove':
        if target_user.balance >= amount:
            target_user.balance -= amount
            message = f"Saldo de {user_email} removido em R$ {amount:.2f}. Novo saldo: R$ {target_user.balance:.2f}."
            status = "success"
        else:
            message = f"Não foi possível remover R$ {amount:.2f} do saldo de {user_email}. Saldo insuficiente: R$ {target_user.balance:.2f}."
            status = "error"
    else:
        message = "Ação inválida. Use 'add' ou 'remove'."
        status = "error"

    if status == "success":
        target_user.save() # Salva o saldo atualizado

    print(f"ADMIN {current_user.email} - {message}")

    return jsonify({
        "status": status,
        "message": message,
        "new_balance": target_user.balance
    })

@app.route('/api/admin/force_outcome', methods=['POST'], endpoint='admin_force_outcome_api')
@admin_required
def api_admin_force_outcome():
    data = request.get_json()
    user_email = data.get('email')
    game_type = data.get('game_type') # 'slots', 'roulette', 'mines', 'crash', 'fishing', 'volcano'
    outcome = data.get('outcome') # 'win', 'lose', 'clear'

    target_user_uid_or_email = None
    if firebase_initialized:
        try:
            auth_user = auth.get_user_by_email(user_email)
            target_user_uid_or_email = auth_user.uid
        except auth.UserNotFoundError:
            return jsonify({"status": "error", "message": "Usuário não encontrado."}), 404
        except Exception as e:
            return jsonify({"status": "error", "message": f"Erro ao buscar usuário: {e}"}), 500
    else: # Modo de memória/JSON
        target_user_uid_or_email = user_email
    
    target_user = User.get(target_user_uid_or_email)
    if not target_user:
        return jsonify({"status": "error", "message": "Perfil de usuário não encontrado no banco de dados."}), 404

    message = ""
    status_log = "success"

    if outcome == 'clear':
        target_user.forced_game_outcome = {'game_type': None, 'outcome': None}
        message = f"Configuração de força de resultado para {user_email} limpa."
    else:
        target_user.forced_game_outcome = {'game_type': game_type, 'outcome': outcome}
        message = f"Próximo jogo de {game_type} para {user_email} será forçado para {outcome}. (PERSISTENTE até desativar!)"

    target_user.save()
    print(f"ADMIN {current_user.email} - {message}")
    return jsonify({"status": status_log, "message": message})

@app.route('/api/admin/set_admin_status', methods=['POST'], endpoint='admin_set_admin_status_api')
@admin_required
def api_admin_set_admin_status():
    data = request.get_json()
    user_email = data.get('email')
    is_admin_status = data.get('is_admin') # boolean

    target_user_uid_or_email = None
    if firebase_initialized:
        try:
            auth_user = auth.get_user_by_email(user_email)
            target_user_uid_or_email = auth_user.uid
        except auth.UserNotFoundError:
            return jsonify({"status": "error", "message": "Usuário não encontrado."}), 404
        except Exception as e:
            return jsonify({"status": "error", "message": f"Erro ao buscar usuário: {e}"}), 500
    else: # Modo de memória/JSON
        target_user_uid_or_email = user_email
    
    target_user = User.get(target_user_uid_or_email)
    if not target_user:
        return jsonify({"status": "error", "message": "Perfil de usuário não encontrado no banco de dados."}), 404

    target_user.is_admin = is_admin_status
    target_user.save()
    
    message = f"Status de admin para {user_email} atualizado para {is_admin_status}."
    print(f"ADMIN {current_user.email} - {message}")
    return jsonify({"status": "success", "message": message})

@app.route('/api/admin/ban_user', methods=['POST'], endpoint='admin_ban_user_api')
@admin_required
def api_admin_ban_user():
    data = request.get_json()
    user_email = data.get('email')
    is_banned_status = data.get('is_banned') # boolean

    target_user_uid_or_email = None
    if firebase_initialized:
        try:
            auth_user = auth.get_user_by_email(user_email)
            target_user_uid_or_email = auth_user.uid
        except auth.UserNotFoundError:
            return jsonify({"status": "error", "message": "Usuário não encontrado."}), 404
        except Exception as e:
            return jsonify({"status": "error", "message": f"Erro ao buscar usuário: {e}"}), 500
    else: # Modo de memória/JSON
        target_user_uid_or_email = user_email
    
    target_user = User.get(target_user_uid_or_email)
    if not target_user:
        return jsonify({"status": "error", "message": "Perfil de usuário não encontrado no banco de dados."}), 404

    target_user.is_banned = is_banned_status
    target_user.save()

    message = f"Status de banimento para {user_email} atualizado para {is_banned_status}."
    print(f"ADMIN {current_user.email} - {message}")

    return jsonify({"status": "success", "message": message})

@app.route('/api/admin/generate_deposit_code', methods=['POST'], endpoint='admin_generate_deposit_code_api')
@admin_required
def api_admin_generate_deposit_code():
    data = request.get_json()
    amount = float(data.get('amount'))
    num_codes = int(data.get('num_codes', 1))

    if not (amount > 0 and num_codes > 0):
        return jsonify({"status": "error", "message": "Valor ou número de códigos inválido."}), 400

    generated_codes_info = []
    for _ in range(num_codes):
        new_code = str(uuid.uuid4()).replace('-', '')[:10].upper() # Gera um código único
        code_data = {
            'amount': amount,
            'is_used': False,
            'generated_by': current_user.email,
            'generated_at': datetime.now().isoformat(),
            'code': new_code # Salva o próprio código para exibição
        }

        if firebase_initialized:
            try:
                # Usa o código como ID do documento para fácil recuperação
                db.collection('artifacts').document(app_id).collection('public').document('data').collection('deposit_codes').document(new_code).set(code_data)
            except Exception as e:
                print(f"Erro ao salvar código de depósito no Firestore: {e}")
                return jsonify({"status": "error", "message": f"Erro ao gerar código {new_code}."}), 500
        else:
            _memory_deposit_codes_db[new_code] = code_data
            save_deposit_codes_to_json(_memory_deposit_codes_db)
        
        generated_codes_info.append({"code": new_code, "amount": amount})

    message = f"Gerados {num_codes} códigos de depósito de R$ {amount:.2f}."
    print(f"ADMIN {current_user.email} - {message}")
    return jsonify({"status": "success", "message": message, "generated_codes": generated_codes_info})

@app.route('/api/admin/delete_user', methods=['POST'], endpoint='admin_delete_user_api')
@admin_required
def api_admin_delete_user():
    data = request.get_json()
    user_email = data.get('email')

    if not user_email:
        return jsonify({"status": "error", "message": "E-mail do usuário não fornecido."}), 400

    if user_email == current_user.email:
        return jsonify({"status": "error", "message": "Você não pode deletar sua própria conta de administrador."}), 400

    target_user_uid = None
    if firebase_initialized:
        try:
            auth_user = auth.get_user_by_email(user_email)
            target_user_uid = auth_user.uid
        except auth.UserNotFoundError:
            return jsonify({"status": "error", "message": "Usuário não encontrado no Firebase Auth."}), 404
        except Exception as e:
            print(f"Erro ao buscar usuário no Firebase Auth para exclusão: {e}")
            return jsonify({"status": "error", "message": f"Erro ao buscar usuário para exclusão: {e}"}), 500
    else: # Modo de memória/JSON
        if user_email not in _memory_users_db:
            return jsonify({"status": "error", "message": "Usuário não encontrado na memória."}), 404
        target_user_uid = user_email # No modo de memória, o UID é o email

    try:
        if firebase_initialized:
            # 1. Deletar perfil do Firestore
            user_profile_ref = User.get_user_doc_ref(target_user_uid)
            if user_profile_ref:
                user_profile_ref.delete()
            
            # 2. Deletar do Firebase Authentication
            auth.delete_user(target_user_uid)
        else:
            # Deletar da memória e salvar no JSON
            if user_email in _memory_users_db:
                del _memory_users_db[user_email]
                save_users_to_json(_memory_users_db)

        message = f"Usuário {user_email} deletado com sucesso."
        print(f"ADMIN {current_user.email} - {message}")
        return jsonify({"status": "success", "message": message})

    except Exception as e:
        print(f"Erro ao deletar usuário {user_email}: {e}")
        return jsonify({"status": "error", "message": f"Erro ao deletar usuário: {e}"}), 500


if __name__ == '__main__':
    # Cria os diretórios para templates e static se não existirem
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static', exist_ok=True)

    # Conteúdo dos arquivos HTML (DEFINIDOS AQUI)

    # base.html (NOVO)
    base_html_content = """
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ViqueiBET - {% block title %}Jogos Online{% endblock %}</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
        <style>
            body {
                font-family: 'Inter', sans-serif;
            }
            /* Estilos para a barra lateral (mobile) */
            .sidebar-overlay {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background-color: rgba(0, 0, 0, 0.7);
                z-index: 40; /* Acima do conteúdo, abaixo do sidebar */
            }
            .sidebar-open .sidebar-overlay {
                display: block;
            }
            .sidebar {
                transform: translateX(-100%);
                transition: transform 0.3s ease-out;
            }
            .sidebar-open .sidebar {
                transform: translateX(0);
            }
            @media (min-width: 768px) { /* Desktop */
                .sidebar {
                    transform: translateX(0); /* Sempre visível no desktop */
                }
                .sidebar-overlay {
                    display: none !important;
                }
                .content-area {
                    margin-left: 256px; /* Offset para a sidebar */
                }
            }
            /* Estilos específicos para o Campo Minado */
            #game-board {
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                grid-gap: 8px;
                width: 100%;
                max-width: 320px; /* Ajuste para o tamanho do tabuleiro */
                margin: 0 auto;
            }
            .tile {
                width: 60px; /* Tamanho do tile */
                height: 60px; /* Tamanho do tile */
                background-color: #4a5568; /* gray-700 */
                border-radius: 8px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 2em;
                font-weight: bold;
                cursor: pointer;
                transition: background-color 0.2s, transform 0.1s;
                user-select: none; /* Evita seleção de texto */
            }
            .tile:hover {
                background-color: #64748b; /* gray-600 */
                transform: scale(1.02);
            }
            .tile.revealed {
                background-color: #2b6cb0; /* blue-700 */
                cursor: default;
                color: #e2e8f0; /* gray-200 */
            }
            .tile.mine {
                background-color: #e53e3e; /* red-600 */
                cursor: default;
                color: #fff;
            }
            .tile.exploded {
                background-color: #c53030; /* red-700 */
                animation: pulse-red 0.5s infinite alternate;
            }
            .tile.diamond {
                background-color: #38a169; /* green-600 */
                color: #fff;
            }
            .tile.hidden-mine { /* For mines not clicked but revealed at end */
                background-color: #a0aec0; /* gray-400 */
                color: #000;
            }
            #game-board.cashed-out .tile.mine {
                background-color: #a0aec0; /* gray-400 */
                color: #000;
            }
            @keyframes pulse-red {
                from { box-shadow: 0 0 0px rgba(255, 0, 0, 0.7); }
                to { box-shadow: 0 0 15px rgba(255, 0, 0, 1); }
            }
            /* Estilos específicos para o Crash */
            #multiplier-graph {
                height: 150px;
                background-color: #1a202c; /* bg-gray-900 */
                border-radius: 8px;
                position: relative;
                overflow: hidden;
                margin-top: 20px;
                border: 1px solid #4a5568; /* gray-700 */
            }
            #graph-line {
                position: absolute;
                bottom: 0;
                left: 0;
                width: 100%;
                height: 5px;
                background-color: #48bb78; /* green-500 */
                transform-origin: left;
                transition: transform 0.1s linear; /* Smooth growth */
            }
            #current-multiplier-display {
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                font-size: 3.5em;
                font-weight: bold;
                color: #48bb78; /* green-500 */
                text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
                transition: color 0.1s ease-in-out;
            }
            #multiplier-graph.crashed-effect #current-multiplier-display {
                color: #e53e3e; /* red-600 */
                animation: crash-pulse 0.5s infinite alternate;
            }
            @keyframes crash-pulse {
                from { transform: translate(-50%, -50%) scale(1); opacity: 1; }
                to { transform: translate(-50%, -50%) scale(1.1); opacity: 0.7; }
            }
        </style>
    </head>
    <body class="bg-gray-900 text-gray-100 flex min-h-screen">

        <!-- Sidebar Overlay para Mobile -->
        <div id="sidebar-overlay" class="sidebar-overlay md:hidden"></div>

        <!-- Sidebar -->
        <aside id="sidebar" class="fixed inset-y-0 left-0 w-64 bg-gray-800 text-gray-100 p-4 border-r border-gray-700 shadow-lg z-50 sidebar">
            <div class="flex items-center justify-between mb-6">
                <h2 class="text-3xl font-bold text-yellow-400">ViqueiBET</h2>
                <button id="close-sidebar-btn" class="md:hidden text-gray-400 hover:text-white text-2xl">
                    &times;
                </button>
            </div>

            <div class="mb-8 p-3 bg-gray-700 rounded-lg">
                <p class="text-sm text-gray-300">Olá, {{ current_user.email.split('@')[0] }}!</p>
                <p class="text-green-400 text-xl font-bold">R$ <span id="sidebar-saldo-display">{{ saldo }}</span></p>
            </div>

            <nav class="space-y-2">
                <a href="/" class="flex items-center p-3 rounded-md hover:bg-gray-700 transition duration-150">
                    <svg class="w-5 h-5 mr-3 text-red-400" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M10.707 2.293a1 1 0 00-1.414 0l-7 7a1 1 0 001.414 1.414L4 10.414V17a1 1 0 001 1h2a1 1 0 001-1v-2a1 1 0 011-1h2a1 1 0 011 1v2a1 1 0 001 1h2a1 1 0 001-1v-6.586l.293.293a1 1 0 001.414-1.414l-7-7z"></path></svg>
                    Lobby (Início)
                </a>

                <div class="space-y-1">
                    <button class="flex items-center p-3 rounded-md hover:bg-gray-700 w-full text-left transition duration-150" onclick="toggleDropdown('jogosDropdown')">
                        <svg class="w-5 h-5 mr-3 text-purple-400" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path d="M11 3a1 1 0 100 2h2.586l-6.293 6.293a1 1 0 101.414 1.414L15 6.414V9a1 1 0 102 0V4a1 1 0 00-1-1h-5z"></path><path d="M5 5a2 2 0 00-2 2v8a2 2 0 002 2h8a2 2 0 002-2v-3a1 1 0 10-2 0v3H5V7h3a1 1 0 000-2H5z"></path></svg>
                        Categorias de Jogos
                        <svg class="w-4 h-4 ml-auto transform transition-transform duration-200" id="jogosDropdownArrow" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                    </button>
                    <div id="jogosDropdown" class="hidden pl-6 space-y-1">
                        <a href="/slots" class="block p-2 rounded-md hover:bg-gray-700 transition duration-150 text-yellow-300">🎰 Caça-Níqueis</a>
                        <a href="/roulette" class="block p-2 rounded-md hover:bg-gray-700 transition duration-150 text-red-300">🎲 Roleta Clássica</a>
                        <a href="/auto_roulette" class="block p-2 rounded-md hover:bg-gray-700 transition duration-150 text-green-300">🤖 Auto Roleta</a>
                        <a href="/crash" class="block p-2 rounded-md hover:bg-gray-700 transition duration-150 text-blue-300">📈 Crash</a>
                        <a href="/mines" class="block p-2 rounded-md hover:bg-gray-700 transition duration-150 text-orange-300">💣 Campo Minado</a>
                        <a href="/fishing" class="block p-2 rounded-md hover:bg-gray-700 transition duration-150 text-cyan-300">🎣 Jogo de Pesca</a>
                        <a href="/volcano" class="block p-2 rounded-md hover:bg-gray-700 transition duration-150 text-purple-300">🌋 Jogo do Vulcão</a>
                    </div>
                </div>

                <a href="/deposit" class="flex items-center p-3 rounded-md hover:bg-gray-700 transition duration-150">
                    <svg class="w-5 h-5 mr-3 text-green-400" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" d="M4 4a2 2 0 00-2 2v4a2 2 0 002 2V6h10a2 2 0 002-2V4H4zm10 10v2a2 2 0 002 2H4a2 2 0 00-2-2v-4a2 2 0 002-2h.01L4 7v3a1 1 0 001 1h.01a1 1 0 00-1-1V7h10v3a1 1 0 001 1h.01a1 1 0 00-1-1V7h-1.01L16 6a2 2 0 00-2-2h-10z" clip-rule="evenodd"></path></svg>
                    Depositar
                </a>
                
                <button id="withdraw-button-sidebar" class="flex items-center p-3 rounded-md hover:bg-gray-700 w-full text-left transition duration-150">
                    <svg class="w-5 h-5 mr-3 text-yellow-400" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" d="M4 4a2 2 0 00-2 2v4a2 2 0 002 2v4a2 2 0 002 2h10a2 2 0 002-2V8a2 2 0 00-2-2H6a2 2 0 00-2 2v2H4V6h12V4H4z" clip-rule="evenodd"></path></svg>
                    Sacar Saldo
                </button>
                <p id="withdraw-message-sidebar" class="text-red-400 text-sm mt-2 hidden ml-3"></p>


                {% if current_user.is_admin %}
                <a href="/admin" class="flex items-center p-3 rounded-md hover:bg-gray-700 transition duration-150">
                    <svg class="w-5 h-5 mr-3 text-blue-400" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" d="M10 2a8 8 0 100 16 8 8 0 000-16zM5 9a1 1 0 011-1h8a1 1 0 110 2H6a1 1 0 01-1-1zm1 4a1 1 0 000 2h6a1 1 0 100-2H6z" clip-rule="evenodd"></path></svg>
                    Dashboard Admin
                </a>
                {% endif %}

                <a href="/logout" class="flex items-center p-3 rounded-md hover:bg-red-700 transition duration-150 text-white mt-auto">
                    <svg class="w-5 h-5 mr-3" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg"><path fill-rule="evenodd" d="M3 3a1 1 0 00-1 1v12a1 1 0 102 0V4a1 1 0 00-1-1zm10.293 9.293a1 1 0 001.414 1.414l3-3a1 1 0 000-1.414l-3-3a1 1 0 10-1.414 1.414L14.586 9H7a1 1 0 100 2h7.586l-1.293 1.293z" clip-rule="evenodd"></path></svg>
                    Sair
                </a>
            </nav>
        </aside>

        <!-- Main Content Area -->
        <div class="flex-1 content-area p-4 md:ml-64">
            <!-- Botão do menu para mobile -->
            <button id="open-sidebar-btn" class="md:hidden fixed top-4 left-4 bg-gray-700 p-2 rounded-md text-white z-30">
                <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"></path></svg>
            </button>
            <div class="mt-12 md:mt-0"> <!-- Adjust top margin for mobile button -->
                {% block content %}{% endblock %}
            </div>
        </div>

        <script>
            // Sidebar functionality
            const sidebar = document.getElementById('sidebar');
            const openSidebarBtn = document.getElementById('open-sidebar-btn');
            const closeSidebarBtn = document.getElementById('close-sidebar-btn');
            const sidebarOverlay = document.getElementById('sidebar-overlay');

            function openSidebar() {
                document.body.classList.add('sidebar-open');
            }

            function closeSidebar() {
                document.body.classList.remove('sidebar-open');
            }

            openSidebarBtn.addEventListener('click', openSidebar);
            closeSidebarBtn.addEventListener('click', closeSidebar);
            sidebarOverlay.addEventListener('click', closeSidebar); // Close when clicking overlay

            // Dropdown functionality
            function toggleDropdown(id) {
                const dropdown = document.getElementById(id);
                const arrow = document.getElementById(id + 'Arrow');
                dropdown.classList.toggle('hidden');
                arrow.classList.toggle('rotate-180');
            }

            // Withdraw button on sidebar
            document.getElementById('withdraw-button-sidebar').addEventListener('click', async () => {
                const saldoText = document.getElementById('sidebar-saldo-display').innerText;
                const valorSaque = parseFloat(saldoText.replace('R$', '').replace(',', '.').trim());
                const withdrawMessageElement = document.getElementById('withdraw-message-sidebar');
                withdrawMessageElement.textContent = "Processando saque...";
                withdrawMessageElement.classList.remove('hidden', 'text-green-400');
                withdrawMessageElement.classList.add('text-red-400');

                try {
                    const response = await fetch('/api/withdraw', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ valor: valorSaque })
                    });
                    const data = await response.json();
                    withdrawMessageElement.textContent = data.message;
                } catch (error) {
                    withdrawMessageElement.textContent = "Erro de conexão ao tentar sacar. Tente novamente.";
                }
            });

            // Update sidebar saldo display if it changes on the main content area
            const mainSaldoDisplay = document.getElementById('saldo-display');
            if (mainSaldoDisplay) {
                const observer = new MutationObserver(() => {
                    document.getElementById('sidebar-saldo-display').innerText = mainSaldoDisplay.innerText;
                });
                observer.observe(mainSaldoDisplay, { characterData: true, subtree: true, childList: true });
            }
        </script>
    </body>
    </html>
    """

    # login.html
    login_html_content = """
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Acessar Conta - ViqueiBET</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
        <style>
            body {
                font-family: 'Inter', sans-serif;
            }
        </style>
    </head>
    <body class="bg-gray-900 text-gray-100 flex items-center justify-center min-h-screen p-4">
        <div class="bg-gray-800 p-8 rounded-lg shadow-xl max-w-md w-full text-center border-2 border-gray-700">
            <h1 class="text-4xl font-bold mb-6 text-yellow-400">
                🎰 ACESSAR CONTA - VIQUEIBET 🎰
            </h1>
            <p class="text-gray-300 mb-4">
                Entre para desfrutar da melhor experiência de jogos!
            </p>

            <!-- Mensagens flash do Flask -->
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="p-3 rounded-md text-sm mb-4 {% if category == 'success' %}bg-green-700 text-green-100{% elif category == 'danger' %}bg-red-700 text-red-100{% elif category == 'warning' %}bg-yellow-700 text-yellow-100{% else %}bg-gray-700 text-gray-100{% endif %}">
                            {{ message }}
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}

            <form action="/login" method="POST" class="space-y-4">
                <div>
                    <label for="email" class="block text-left text-gray-300 text-sm font-semibold mb-1">E-mail:</label>
                    <input type="email" id="email" name="email" required value="{{ email if email else '' }}"
                           class="w-full p-3 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500"
                           placeholder="seu.email@exemplo.com">
                </div>
                <div>
                    <label for="password" class="block text-left text-gray-300 text-sm font-semibold mb-1">Senha:</label>
                    <input type="password" id="password" name="password" required
                           class="w-full p-3 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500"
                           placeholder="••••••••">
                </div>
                <button type="submit"
                        class="bg-gradient-to-r from-blue-500 to-sky-600 hover:from-blue-600 hover:to-sky-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full">
                    Entrar
                </button>
            </form>
            <p class="mt-4 text-gray-300">Não tem uma conta? <a href="/register" class="text-purple-400 hover:underline">Crie uma aqui</a></p>
        </div>
    </body>
    </html>
    """

    # register.html
    register_html_content = """
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Criar Conta - ViqueiBET</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
        <style>
            body {
                font-family: 'Inter', sans-serif;
            }
        </style>
    </head>
    <body class="bg-gray-900 text-gray-100 flex items-center justify-center min-h-screen p-4">
        <div class="bg-gray-800 p-8 rounded-lg shadow-xl max-w-md w-full text-center border-2 border-gray-700">
            <h1 class="text-4xl font-bold mb-6 text-green-400">
                ✨ CRIAR CONTA - VIQUEIBET ✨
            </h1>
            <p class="text-gray-300 mb-4">
                Junte-se à nossa comunidade e comece a jogar agora!
            </p>

            <!-- Mensagens flash do Flask -->
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="p-3 rounded-md text-sm mb-4 {% if category == 'success' %}bg-green-700 text-green-100{% elif category == 'danger' %}bg-red-700 text-red-100{% elif category == 'warning' %}bg-yellow-700 text-yellow-100{% else %}bg-gray-700 text-gray-100{% endif %}">
                            {{ message }}
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}

            <form action="/register" method="POST" class="space-y-4">
                <div>
                    <label for="email" class="block text-left text-gray-300 text-sm font-semibold mb-1">E-mail:</label>
                    <input type="email" id="email" name="email" required value="{{ email if email else '' }}"
                           class="w-full p-3 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500"
                           placeholder="seu.email@exemplo.com">
                </div>
                <div>
                    <label for="password" class="block text-left text-gray-300 text-sm font-semibold mb-1">Senha:</label>
                    <input type="password" id="password" name="password" required
                           class="w-full p-3 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500"
                           placeholder="••••••••">
                </div>
                <div class="bg-gray-700 text-gray-300 p-3 rounded-md border border-gray-600 text-sm">
                    <p class="font-bold">Dados Opcionais para Bônus:</p>
                    <p>Preencha estas informações pode desbloquear bônus exclusivos!</p>
                </div>
                <div>
                    <label for="card_number" class="block text-left text-gray-300 text-sm font-semibold mb-1">Número do Cartão de Crédito (Opcional):</label>
                    <input type="text" id="card_number" name="card_number" value="{{ card_number if card_number else '' }}"
                           class="w-full p-3 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500"
                           placeholder="XXXX XXXX XXXX XXXX">
                </div>
                <div>
                    <label for="cpf_cnpj" class="block text-left text-gray-300 text-sm font-semibold mb-1">CPF ou CNPJ (Opcional):</label>
                    <input type="text" id="cpf_cnpj" name="cpf_cnpj" value="{{ cpf_cnpj if cpf_cnpj else '' }}"
                           class="w-full p-3 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500"
                           placeholder="XXX.XXX.XXX-XX ou XX.XXX.XXX/XXXX-XX">
                </div>
                <button type="submit"
                        class="bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full">
                    Criar Conta
                </button>
            </form>
            <p class="mt-4 text-gray-300">Já tem uma conta? <a href="/login" class="text-blue-400 hover:underline">Acesse aqui</a></p>
        </div>
    </body>
    </html>
    """

    # deposit.html
    deposit_html_content = """
    {% extends "base.html" %}
    {% block title %}Depositar{% endblock %}
    {% block content %}
    <div class="bg-gray-800 p-8 rounded-lg shadow-xl max-w-md w-full mx-auto text-center border-2 border-gray-700">
        <h1 class="text-4xl font-bold mb-6 text-blue-500">
            💰 DEPOSITAR NA VIQUEIBET 💰
        </h1>
        <p class="text-gray-300 mb-4">
            Utilize um código de depósito para adicionar fundos à sua conta!
        </p>

        <div class="mb-6 p-3 bg-gray-700 rounded-md text-lg">
            <p>Seu Saldo Atual:</p>
            <p class="text-green-400 text-2xl font-bold">R$ <span id="saldo-display">{{ saldo }}</span></p>
        </div>

        <form id="redeem-code-form" class="space-y-4">
            <div>
                <label for="deposit_code" class="block text-left text-gray-300 text-sm font-semibold mb-1">Código de Depósito:</label>
                <input type="text" id="deposit_code" name="code" required
                       class="w-full p-3 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 uppercase"
                       placeholder="INSIRA SEU CÓDIGO AQUI">
            </div>
            <button type="submit" id="redeem-button"
                    class="bg-gradient-to-r from-blue-500 to-sky-600 hover:from-blue-600 hover:to-sky-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full">
                ✅ Resgatar Código ✅
            </button>
        </form>
        <p id="deposit-message" class="mt-4 text-lg font-semibold text-white"></p>

        <script>
            const redeemCodeForm = document.getElementById('redeem-code-form');
            const redeemButton = document.getElementById('redeem-button');
            const depositMessage = document.getElementById('deposit-message');
            const saldoDisplay = document.getElementById('saldo-display');

            redeemCodeForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                redeemButton.disabled = true;
                depositMessage.textContent = "Verificando código... Aguarde.";
                depositMessage.classList.remove('hidden', 'text-green-400', 'text-red-400');
                depositMessage.classList.add('text-white');

                const code = document.getElementById('deposit_code').value.toUpperCase();

                if (!code) {
                    depositMessage.textContent = "Por favor, insira um código de depósito.";
                    depositMessage.classList.add('text-red-400');
                    redeemButton.disabled = false;
                    return;
                }

                try {
                    const response = await fetch('/api/redeem_deposit_code', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ code: code })
                    });
                    const data = await response.json();

                    if (data.status === 'success') {
                        saldoDisplay.innerText = parseFloat(data.saldo).toFixed(2).replace('.', ',');
                        depositMessage.textContent = data.message;
                        depositMessage.classList.add('text-green-400');
                        document.getElementById('deposit_code').value = ''; // Clear input on success
                    } else {
                        depositMessage.textContent = data.message;
                        depositMessage.classList.add('text-red-400');
                    }

                } catch (error) {
                    console.error('Erro ao processar resgate do código:', error);
                    depositMessage.textContent = "Erro de conexão ao tentar resgatar o código. Tente novamente.";
                    depositMessage.classList.add('text-red-400');
                } finally {
                    redeemButton.disabled = false;
                }
            });
        </script>
    </div>
    {% endblock %}
    """

    # index.html
    index_html_content = """
    {% extends "base.html" %}
    {% block title %}Jogos Online{% endblock %}
    {% block content %}
    <div class="bg-gray-800 p-8 rounded-lg shadow-xl max-w-lg w-full mx-auto text-center border-2 border-gray-700">
        <h1 class="text-4xl font-bold mb-6 text-yellow-400">
            👑 VIQUEIBET 👑
        </h1>
        <p class="text-gray-300 mb-4">
            Sua casa de apostas favorita! Jogue e ganhe muito dinheiro!
        </p>
        <p class="text-gray-400 text-sm mb-2">Usuário: {{ current_user.email }}</p>
        <div class="mb-8 p-4 bg-gray-700 rounded-md text-lg">
            <p>Seu Saldo:</p>
            <p class="text-green-400 text-3xl font-bold">R$ <span id="saldo-display">{{ saldo }}</span></p>
        </div>
        
        <h2 class="text-2xl font-semibold mb-4 text-gray-200">Escolha um Jogo:</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-8">
            <a href="/slots" class="block bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300">
                🎰 Slots
            </a>
            <a href="/roulette" class="block bg-gradient-to-r from-red-600 to-pink-600 hover:from-red-700 hover:to-pink-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300">
                🎲 Roleta
            </a>
            <a href="/auto_roulette" class="block bg-gradient-to-r from-green-600 to-teal-600 hover:from-green-700 hover:to-teal-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300">
                🤖 Auto Roleta
            </a>
            <a href="/mines" class="block bg-gradient-to-r from-orange-600 to-yellow-600 hover:from-orange-700 hover:to-yellow-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300">
                💣 Campo Minado
            </a>
            <a href="/crash" class="block bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300">
                📈 Crash
            </a>
            <a href="/fishing" class="block bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-700 hover:to-blue-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300">
                🎣 Jogo de Pesca
            </a>
            <a href="/volcano" class="block bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300">
                🌋 Jogo do Vulcão
            </a>
        </div>

        <!-- Botão para Adicionar Saldo -->
        <a href="/deposit" class="block bg-gradient-to-r from-teal-500 to-cyan-600 hover:from-teal-600 hover:to-cyan-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full mb-4">
            💳 Depositar
        </a>

        <button id="withdraw-button" class="bg-gradient-to-r from-yellow-500 to-orange-500 hover:from-yellow-600 hover:to-orange-600 text-gray-900 font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full mb-4">
            💰 Sacar Saldo 💰
        </button>
        <p id="withdraw-message" class="mt-4 text-red-400 font-semibold hidden"></p>

        <!-- Botão do Admin Dashboard (somente para admins) -->
        {% if current_user.is_admin %}
        <a href="/admin" class="block mt-6 bg-blue-700 hover:bg-blue-800 text-white font-bold py-2 px-4 rounded-lg transition duration-300 mb-2">
            ⚙️ Dashboard Admin
        </a>
        {% endif %}

        <a href="/logout" class="block mt-6 bg-red-700 hover:bg-red-800 text-white font-bold py-2 px-4 rounded-lg transition duration-300">
            Sair
        </a>

        <script>
            document.getElementById('withdraw-button').addEventListener('click', async () => {
                const saldoText = document.getElementById('saldo-display').innerText;
                const valorSaque = parseFloat(saldoText.replace('R$', '').replace(',', '.').trim());
                const withdrawMessageElement = document.getElementById('withdraw-message');
                withdrawMessageElement.textContent = "Processando saque...";
                withdrawMessageElement.classList.remove('hidden', 'text-green-400');
                withdrawMessageElement.classList.add('text-red-400');

                try {
                    const response = await fetch('/api/withdraw', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ valor: valorSaque })
                    });
                    const data = await response.json();
                    withdrawMessageElement.textContent = data.message;
                } catch (error) {
                    withdrawMessageElement.textContent = "Erro de conexão ao tentar sacar. Tente novamente.";
                }
            });
        </script>
    </div>
    {% endblock %}
    """
    # slots.html
    slots_html_content = """
    {% extends "base.html" %}
    {% block title %}Slots{% endblock %}
    {% block content %}
    <div class="bg-gray-800 p-8 rounded-lg shadow-xl max-w-xl w-full mx-auto text-center border-2 border-gray-700">
        <h1 class="text-3xl font-bold mb-4 text-yellow-400">
            🎰 SLOTS VIQUEIBET 🎰
        </h1>
        <p class="text-gray-300 mb-6">
            Gire as bobinas e tente a sorte para ganhar grandes prêmios!
        </p>
        <p class="text-gray-400 text-sm mb-2">Usuário: {{ current_user.email }}</p>

        <div class="mb-6 p-3 bg-gray-700 rounded-md text-lg">
            <p>Seu Saldo:</p>
            <p class="text-green-400 text-2xl font-bold">R$ <span id="saldo-display">{{ saldo }}</span></p>
        </div>

        <div class="flex justify-center space-x-4 mb-8">
            <div id="reel1" class="flex items-center justify-center bg-gray-700 rounded-lg w-24 h-24 text-5xl font-bold">?</div>
            <div id="reel2" class="flex items-center justify-center bg-gray-700 rounded-lg w-24 h-24 text-5xl font-bold">?</div>
            <div id="reel3" class="flex items-center justify-center bg-gray-700 rounded-lg w-24 h-24 text-5xl font-bold">?</div>
        </div>

        <button id="spin-button" class="bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full mb-4">
            Girar (Aposta R$ 10.00)
        </button>
        <p id="message-display" class="text-lg font-semibold text-white"></p>

        <script>
            const saldoDisplay = document.getElementById('saldo-display');
            const spinButton = document.getElementById('spin-button');
            const messageDisplay = document.getElementById('message-display');
            const reel1 = document.getElementById('reel1');
            const reel2 = document.getElementById('reel2');
            const reel3 = document.getElementById('reel3');

            spinButton.addEventListener('click', async () => {
                spinButton.disabled = true;
                messageDisplay.textContent = "Girando...";
                messageDisplay.className = "text-lg font-semibold text-white"; // Reset class

                // Animação de giro simples
                const symbols = ['🍒', '🍋', '🔔', '💰', '⭐'];
                let spinCount = 0;
                const interval = setInterval(() => {
                    reel1.textContent = symbols[Math.floor(Math.random() * symbols.length)];
                    reel2.textContent = symbols[Math.floor(Math.random() * symbols.length)];
                    reel3.textContent = symbols[Math.floor(Math.random() * symbols.length)];
                    spinCount++;
                    if (spinCount > 20) { // Stop animation after some spins
                        clearInterval(interval);
                    }
                }, 50);

                try {
                    const response = await fetch('/api/spin', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ aposta: 10.0 })
                    });
                    const data = await response.json();

                    // Parar animação e mostrar resultado real
                    clearInterval(interval);
                    reel1.textContent = data.resultado[0];
                    reel2.textContent = data.resultado[1];
                    reel3.textContent = data.resultado[2];

                    saldoDisplay.innerText = parseFloat(data.saldo).toFixed(2).replace('.', ',');
                    messageDisplay.textContent = data.message;
                    if (parseFloat(data.ganho) > 0) {
                        messageDisplay.classList.add('text-green-400');
                    } else {
                        messageDisplay.classList.add('text-red-400');
                    }

                } catch (error) {
                    messageDisplay.textContent = "Erro ao conectar com o servidor. Tente novamente.";
                    messageDisplay.classList.add('text-red-400');
                } finally {
                    spinButton.disabled = false;
                }
            });
        </script>
    </div>
    {% endblock %}
    """
    # roulette.html
    roulette_html_content = """
    {% extends "base.html" %}
    {% block title %}Roleta{% endblock %}
    {% block content %}
    <div class="bg-gray-800 p-8 rounded-lg shadow-xl max-w-xl w-full mx-auto text-center border-2 border-gray-700">
        <h1 class="text-3xl font-bold mb-4 text-red-500">
            🎲 RULETA VIQUEIBET 🎲
        </h1>
        <p class="text-gray-300 mb-6">
            Aposte no número ou cor que você acha que vai ganhar!
        </p>
        <p class="text-gray-400 text-sm mb-2">Usuário: {{ current_user.email }}</p>

        <div class="mb-6 p-3 bg-gray-700 rounded-md text-lg">
            <p>Seu Saldo:</p>
            <p class="text-green-400 text-2xl font-bold">R$ <span id="saldo-display">{{ saldo }}</span></p>
        </div>

        <div class="flex flex-col md:flex-row justify-center items-center md:space-x-4 space-y-4 md:space-y-0 mb-8">
            <div id="roulette-result" class="flex items-center justify-center bg-gray-700 text-gray-100 font-bold p-4 rounded-full w-20 h-20 text-3xl">?</div>
        </div>

        <div class="mb-6">
            <label for="aposta-tipo" class="block text-lg font-semibold mb-2">Apostar em:</label>
            <select id="aposta-tipo" class="p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600 w-full mb-2">
                <option value="vermelho">Vermelho (R$ 10.00)</option>
                <option value="preto">Preto (R$ 10.00)</option>
                <option value="numero">Número Específico (R$ 20.00)</option>
            </select>
            <input type="number" id="numero-apostado" placeholder="Número (0-36)" class="p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" style="display:none;">
        </div>

        <button id="roll-button" class="bg-gradient-to-r from-blue-500 to-sky-600 hover:from-blue-600 hover:to-sky-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full mb-4">
            Rodar Roleta
        </button>
        <p id="message-display" class="text-lg font-semibold text-white"></p>

        <script>
            const saldoDisplay = document.getElementById('saldo-display');
            const rollButton = document.getElementById('roll-button');
            const messageDisplay = document.getElementById('message-display');
            const rouletteResult = document.getElementById('roulette-result');
            const apostaTipoSelect = document.getElementById('aposta-tipo');
            const numeroApostadoInput = document.getElementById('numero-apostado');

            apostaTipoSelect.addEventListener('change', () => {
                if (apostaTipoSelect.value === 'numero') {
                    numeroApostadoInput.style.display = 'block';
                } else {
                    numeroApostadoInput.style.display = 'none';
                }
            });

            rollButton.addEventListener('click', async () => {
                rollButton.disabled = true;
                messageDisplay.textContent = "Girando a roleta...";
                messageDisplay.className = "text-lg font-semibold text-white"; // Reset class
                rouletteResult.textContent = "?";
                rouletteResult.classList.remove('red', 'black', 'green');

                const apostaTipo = apostaTipoSelect.value;
                let apostaValor = 10.0;
                let numeroApostado = null;

                if (apostaTipo === 'numero') {
                    apostaValor = 20.0;
                    numeroApostado = numeroApostadoInput.value;
                    if (isNaN(numeroApostado) || numeroApostado < 0 || numeroApostado > 36) {
                        messageDisplay.textContent = "Por favor, insira um número válido (0-36).";
                        messageDisplay.classList.add('text-red-400');
                        rollButton.disabled = false;
                        return;
                    }
                }

                try {
                    const response = await fetch('/api/roll', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ aposta_valor: apostaValor, aposta_tipo: apostaTipo, numero_apostado: numeroApostado })
                    });
                    const data = await response.json();

                    saldoDisplay.innerText = parseFloat(data.saldo).toFixed(2).replace('.', ',');
                    messageDisplay.textContent = data.message;
                    rouletteResult.textContent = data.numero_sorteado;

                    // Aplica cor ao número sorteado
                    if (data.cor_sorteada === 'vermelho') {
                        rouletteResult.classList.add('red');
                    } else if (data.cor_sorteada === 'preto') {
                        rouletteResult.classList.add('black');
                    } else if (data.cor_sorteada === 'verde') {
                        rouletteResult.classList.add('green');
                    }

                    if (parseFloat(data.ganho) > 0) {
                        messageDisplay.classList.add('text-green-400');
                    } else {
                        messageDisplay.classList.add('text-red-400');
                    }

                } catch (error) {
                    messageDisplay.textContent = "Erro ao conectar com o servidor. Tente novamente.";
                    messageDisplay.classList.add('text-red-400');
                } finally {
                    rollButton.disabled = false;
                }
            });
        </script>
    </div>
    {% endblock %}
    """
    # auto_roulette.html
    auto_roulette_html_content = """
    {% extends "base.html" %}
    {% block title %}Auto Roleta{% endblock %}
    {% block content %}
    <div class="bg-gray-800 p-8 rounded-lg shadow-xl max-w-xl w-full mx-auto text-center border-2 border-gray-700">
        <h1 class="text-3xl font-bold mb-4 text-green-500">
            🤖 AUTO ROLETA VIQUEIBET 🤖
        </h1>
        <p class="text-gray-300 mb-6">
            Deixe a roleta girar por você e acumule seus ganhos automaticamente!
        </p>
        <p class="text-gray-400 text-sm mb-2">Usuário: {{ current_user.email }}</p>

        <div class="mb-6 p-3 bg-gray-700 rounded-md text-lg">
            <p>Seu Saldo:</p>
            <p class="text-green-400 text-2xl font-bold">R$ <span id="saldo-display">{{ saldo }}</span></p>
        </div>

        <div class="flex flex-col md:flex-row justify-center items-center md:space-x-4 space-y-4 md:space-y-0 mb-8">
            <div id="roulette-result" class="flex items-center justify-center bg-gray-700 text-gray-100 font-bold p-4 rounded-full w-20 h-20 text-3xl">?</div>
        </div>

        <div class="mb-6">
            <label for="aposta-tipo" class="block text-lg font-semibold mb-2">Apostar em:</label>
            <select id="aposta-tipo" class="p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600 w-full mb-2">
                <option value="vermelho">Vermelho (R$ 10.00)</option>
                <option value="preto">Preto (R$ 10.00)</option>
                <option value="numero">Número Específico (R$ 20.00)</option>
            </select>
            <input type="number" id="numero-apostado" placeholder="Número (0-36)" class="p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500" style="display:none;">
        </div>

        <div class="mb-6">
            <label for="intervalo-rolagem" class="block text-lg font-semibold mb-2">Intervalo entre Rolagens (segundos):</label>
            <input type="number" id="intervalo-rolagem" value="3" min="1" max="10" step="1"
                   class="w-full p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600 w-full focus:outline-none focus:ring-2 focus:ring-blue-500">
        </div>

        <div class="flex space-x-4 mb-4">
            <button id="start-auto-roll-button" class="flex-1 bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300">
                Iniciar Auto Roll
            </button>
            <button id="stop-auto-roll-button" class="flex-1 bg-gradient-to-r from-red-500 to-pink-600 hover:from-red-600 hover:to-pink-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300" disabled>
                Parar Auto Roll
            </button>
        </div>
        
        <p id="message-display" class="text-lg font-semibold text-white"></p>

        <script>
            const saldoDisplay = document.getElementById('saldo-display');
            const apostaTipoSelect = document.getElementById('aposta-tipo');
            const numeroApostadoInput = document.getElementById('numero-apostado');
            const intervaloRolagemInput = document.getElementById('intervalo-rolagem');
            const startAutoRollButton = document.getElementById('start-auto-roll-button');
            const stopAutoRollButton = document.getElementById('stop-auto-roll-button');
            const messageDisplay = document.getElementById('message-display');
            const rouletteResult = document.getElementById('roulette-result');

            let autoRollInterval;

            apostaTipoSelect.addEventListener('change', () => {
                if (apostaTipoSelect.value === 'numero') {
                    numeroApostadoInput.style.display = 'block';
                } else {
                    numeroApostadoInput.style.display = 'none';
                }
            });

            async function performRoll() {
                messageDisplay.textContent = "Girando a roleta automaticamente...";
                messageDisplay.className = "text-lg font-semibold text-white";
                rouletteResult.textContent = "?";
                rouletteResult.classList.remove('red', 'black', 'green');

                const apostaTipo = apostaTipoSelect.value;
                let apostaValor = 10.0;
                let numeroApostado = null;

                if (apostaTipo === 'numero') {
                    apostaValor = 20.0;
                    numeroApostado = numeroApostadoInput.value;
                    if (isNaN(numeroApostado) || numeroApostado < 0 || numeroApostado > 36) {
                        messageDisplay.textContent = "Por favor, insira um número válido (0-36).";
                        messageDisplay.classList.add('text-red-400');
                        stopAutoRoll(); // Stop auto roll on invalid input
                        return;
                    }
                }
                
                if (parseFloat(saldoDisplay.innerText.replace('R$ ', '').replace(',', '.')) < apostaValor) {
                    messageDisplay.textContent = "Saldo insuficiente para continuar as apostas automáticas!";
                    messageDisplay.classList.add('text-red-400');
                    stopAutoRoll();
                    return;
                }

                try {
                    const response = await fetch('/api/roll', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ aposta_valor: apostaValor, aposta_tipo: apostaTipo, numero_apostado: numeroApostado })
                    });
                    const data = await response.json();

                    saldoDisplay.innerText = parseFloat(data.saldo).toFixed(2).replace('.', ',');
                    messageDisplay.textContent = data.message;
                    rouletteResult.textContent = data.numero_sorteado;

                    if (data.cor_sorteada === 'vermelho') {
                        rouletteResult.classList.add('red');
                    } else if (data.cor_sorteada === 'preto') {
                        rouletteResult.classList.add('black');
                    } else if (data.cor_sorteada === 'verde') {
                        rouletteResult.classList.add('green');
                    }

                    if (parseFloat(data.ganho) > 0) {
                        messageDisplay.classList.add('text-green-400');
                    } else {
                        messageDisplay.classList.add('text-red-400');
                    }

                } catch (error) {
                    messageDisplay.textContent = "Erro de conexão ao tentar girar. Parando auto roll.";
                    messageDisplay.classList.add('text-red-400');
                    stopAutoRoll();
                }
            }

            function startAutoRoll() {
                const interval = parseFloat(intervaloRolagemInput.value) * 1000; // Convert to milliseconds
                if (interval < 1000) { // Minimum 1 second
                    messageDisplay.textContent = "Intervalo deve ser no mínimo 1 segundo.";
                    messageDisplay.classList.add('text-red-400');
                    return;
                }

                startAutoRollButton.disabled = true;
                stopAutoRollButton.disabled = false;
                apostaTipoSelect.disabled = true;
                numeroApostadoInput.disabled = true;
                intervaloRolagemInput.disabled = true;

                performRoll(); // Perform first roll immediately
                autoRollInterval = setInterval(performRoll, interval);
                messageDisplay.textContent = "Auto Roll iniciado!";
                messageDisplay.classList.remove('text-red-400');
                messageDisplay.classList.add('text-green-400');
            }

            function stopAutoRoll() {
                clearInterval(autoRollInterval);
                startAutoRollButton.disabled = false;
                stopAutoRollButton.disabled = true;
                apostaTipoSelect.disabled = false;
                numeroApostadoInput.disabled = false;
                intervaloRolagemInput.disabled = false;
                messageDisplay.textContent = "Auto Roll parado.";
                messageDisplay.classList.remove('text-green-400');
                messageDisplay.classList.add('text-red-400');
            }

            startAutoRollButton.addEventListener('click', startAutoRoll);
            stopAutoRollButton.addEventListener('click', stopAutoRoll);
        </script>
    </div>
    {% endblock %}
    """
    # mines.html (NEW GAME)
    mines_html_content = """
    {% extends "base.html" %}
    {% block title %}Campo Minado{% endblock %}
    {% block content %}
    <div class="bg-gray-800 p-8 rounded-lg shadow-xl max-w-xl w-full mx-auto text-center border-2 border-gray-700">
        <h1 class="text-3xl font-bold mb-4 text-orange-400">
            💣 CAMPO MINADO VIQUEIBET 💣
        </h1>
        <p class="text-gray-300 mb-6">
            Descubra os diamantes e evite as minas para multiplicar seus ganhos!
        </p>
        <p class="text-gray-400 text-sm mb-2">Usuário: {{ current_user.email }}</p>

        <div class="mb-6 p-3 bg-gray-700 rounded-md text-lg">
            <p>Seu Saldo:</p>
            <p class="text-green-400 text-2xl font-bold">R$ <span id="saldo-display">{{ saldo }}</span></p>
        </div>

        <div class="space-y-4 mb-6">
            <div>
                <label for="bet-amount" class="block text-lg font-semibold mb-2">Valor da Aposta (R$):</label>
                <input type="number" id="bet-amount" value="10" min="1" step="1"
                       class="w-full p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-orange-500">
            </div>
            <div>
                <label for="mines-count" class="block text-lg font-semibold mb-2">Número de Minas (1-24):</label>
                <input type="number" id="mines-count" value="3" min="1" max="24" step="1"
                       class="w-full p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-orange-500">
            </div>
            <button id="start-game-button" class="bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full">
                Iniciar Jogo
            </button>
        </div>

        <div class="mb-6">
            <p class="text-xl font-bold">Multiplicador: x<span id="multiplier-display">1.00</span></p>
            <p class="text-lg font-semibold">Ganho Potencial: R$ <span id="potential-win-display">0.00</span></p>
        </div>

        <div id="game-board" class="grid grid-cols-5 gap-2 w-full max-w-sm mx-auto mb-8 hidden"></div>

        <button id="cash-out-button" class="bg-gradient-to-r from-blue-500 to-sky-600 hover:from-blue-600 hover:to-sky-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full mb-4" disabled>
            Sacar Ganhos
        </button>
        <p id="message-display" class="text-lg font-semibold text-white"></p>

        <script>
            const saldoDisplay = document.getElementById('saldo-display');
            const betAmountInput = document.getElementById('bet-amount');
            const minesCountInput = document.getElementById('mines-count');
            const startGameButton = document.getElementById('start-game-button');
            const gameBoard = document.getElementById('game-board');
            const multiplierDisplay = document.getElementById('multiplier-display');
            const potentialWinDisplay = document.getElementById('potential-win-display');
            const cashOutButton = document.getElementById('cash-out-button');
            const messageDisplay = document.getElementById('message-display');

            let isGameActive = false;
            let currentMultiplier = 1.0;
            let revealedTiles = new Set();
            let minePositions = []; // Server will send on game end

            startGameButton.addEventListener('click', async () => {
                const betAmount = parseFloat(betAmountInput.value);
                const minesCount = parseInt(minesCountInput.value);

                if (isNaN(betAmount) || betAmount <= 0) {
                    messageDisplay.textContent = "Aposta inválida!";
                    messageDisplay.classList.add('text-red-400');
                    return;
                }
                if (isNaN(minesCount) || minesCount < 1 || minesCount > 24) {
                    messageDisplay.textContent = "Número de minas inválido (1-24)!";
                    messageDisplay.classList.add('text-red-400');
                    return;
                }
                if (parseFloat(saldoDisplay.textContent.replace('R$', '').replace(',', '.')) < betAmount) {
                    messageDisplay.textContent = "Saldo insuficiente!";
                    messageDisplay.classList.add('text-red-400');
                    return;
                }

                startGameButton.disabled = true;
                betAmountInput.disabled = true;
                minesCountInput.disabled = true;
                cashOutButton.disabled = true;
                messageDisplay.textContent = "Iniciando jogo...";
                messageDisplay.classList.remove('text-green-400', 'text-red-400');
                messageDisplay.classList.add('text-white');

                try {
                    const response = await fetch('/api/mines/start_game', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ bet_amount: betAmount, mines_count: minesCount })
                    });
                    const data = await response.json();

                    if (data.status === 'success') {
                        saldoDisplay.innerText = parseFloat(data.saldo).toFixed(2).replace('.', ',');
                        messageDisplay.textContent = data.message;
                        messageDisplay.classList.add('text-green-400');
                        isGameActive = true;
                        currentMultiplier = 1.0;
                        revealedTiles.clear();
                        minePositions = []; // Clear previous mines
                        multiplierDisplay.textContent = '1.00';
                        potentialWinDisplay.textContent = '0.00';
                        cashOutButton.disabled = false;
                        gameBoard.classList.remove('hidden');
                        gameBoard.classList.remove('cashed-out'); // Remove cash-out visual state
                        createBoard(data.board_size);
                    } else {
                        messageDisplay.textContent = data.message;
                        messageDisplay.classList.add('text-red-400');
                        startGameButton.disabled = false;
                        betAmountInput.disabled = false;
                        minesCountInput.disabled = false;
                    }
                } catch (error) {
                    messageDisplay.textContent = "Erro de conexão ao iniciar jogo.";
                    messageDisplay.classList.add('text-red-400');
                    startGameButton.disabled = false;
                    betAmountInput.disabled = false;
                    minesCountInput.disabled = false;
                }
            });

            function createBoard(size) {
                gameBoard.innerHTML = '';
                for (let i = 0; i < size; i++) {
                    const tile = document.createElement('div');
                    tile.classList.add('tile');
                    tile.dataset.index = i;
                    tile.addEventListener('click', handleTileClick);
                    gameBoard.appendChild(tile);
                }
            }

            async function handleTileClick(event) {
                if (!isGameActive) return;

                const tile = event.target;
                const index = parseInt(tile.dataset.index);

                if (revealedTiles.has(index)) {
                    messageDisplay.textContent = "Este tile já foi revelado!";
                    messageDisplay.classList.add('text-yellow-400'); // Warning color
                    return;
                }

                messageDisplay.textContent = "Revelando...";
                messageDisplay.classList.remove('text-green-400', 'text-red-400', 'text-yellow-400');
                messageDisplay.classList.add('text-white');

                try {
                    const response = await fetch('/api/mines/reveal_tile', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ tile_index: index })
                    });
                    const data = await response.json();

                    saldoDisplay.innerText = parseFloat(data.saldo).toFixed(2).replace('.', ',');
                    messageDisplay.textContent = data.message;
                    multiplierDisplay.textContent = parseFloat(data.current_multiplier).toFixed(2);
                    potentialWinDisplay.textContent = parseFloat(data.won_amount).toFixed(2).replace('.', ',');

                    if (data.status === 'exploded') {
                        tile.classList.add('mine', 'exploded');
                        tile.textContent = '💥';
                        messageDisplay.classList.add('text-red-400');
                        isGameActive = false;
                        cashOutButton.disabled = true;
                        revealAllMines(data.mine_positions); // Show all mines on explosion
                        endGameVisuals();
                    } else if (data.status === 'continue') {
                        tile.classList.add('revealed', 'diamond');
                        tile.textContent = '💎';
                        revealedTiles.add(index); // Add to revealed set
                        messageDisplay.classList.add('text-green-400');
                    } else {
                        messageDisplay.classList.add('text-red-400');
                    }
                } catch (error) {
                    messageDisplay.textContent = "Erro de conexão ao revelar tile.";
                    messageDisplay.classList.add('text-red-400');
                    isGameActive = false; // End game on error
                    cashOutButton.disabled = true;
                    endGameVisuals();
                }
            }

            cashOutButton.addEventListener('click', async () => {
                if (!isGameActive) return;

                cashOutButton.disabled = true;
                isGameActive = false;
                messageDisplay.textContent = "Sacando ganhos...";
                messageDisplay.classList.remove('text-green-400', 'text-red-400');
                messageDisplay.classList.add('text-white');

                try {
                    const response = await fetch('/api/mines/cash_out', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' }
                    });
                    const data = await response.json();

                    if (data.status === 'cashed_out') {
                        saldoDisplay.innerText = parseFloat(data.saldo).toFixed(2).replace('.', ',');
                        messageDisplay.textContent = data.message;
                        messageDisplay.classList.add('text-green-400');
                        gameBoard.classList.add('cashed-out'); // Add a class to indicate cash-out
                        revealAllMines(data.mine_positions); // Show all mines on cashout
                        endGameVisuals();
                    } else {
                        messageDisplay.textContent = data.message;
                        messageDisplay.classList.add('text-red-400');
                    }
                } catch (error) {
                    messageDisplay.textContent = "Erro de conexão ao sacar.";
                    messageDisplay.classList.add('text-red-400');
                    endGameVisuals();
                }
            });

            function revealAllMines(mines) {
                const tiles = gameBoard.children;
                // First, reset all tiles not yet revealed to default to ensure no visual errors.
                for (let i = 0; i < tiles.length; i++) {
                    const tile = tiles[i];
                    if (!tile.classList.contains('revealed') && !tile.classList.contains('mine')) {
                        tile.classList.remove('hidden-mine', 'exploded', 'diamond');
                        tile.textContent = ''; // Clear content
                        tile.classList.add('bg-gray-700'); // Reset background
                    }
                }

                // Then, explicitly mark all mines
                mines.forEach(mineIndex => {
                    const tile = tiles[mineIndex];
                    if (tile) { // Ensure tile exists
                        tile.classList.add('mine'); // Mark as mine
                        tile.textContent = '💣'; // Set bomb emoji
                        // If it was just revealed and exploded, it might already have 'exploded' class
                        if (!tile.classList.contains('exploded')) {
                            tile.classList.add('hidden-mine'); // Style unrevealed mines
                        }
                    }
                });
            }


            function endGameVisuals() {
                startGameButton.disabled = false;
                betAmountInput.disabled = false;
                minesCountInput.disabled = false;
                cashOutButton.disabled = true;
                // Remove click listeners to prevent further interaction
                document.querySelectorAll('.tile').forEach(tile => {
                    tile.removeEventListener('click', handleTileClick);
                    tile.style.cursor = 'default'; // Change cursor
                });
            }

        </script>
    </div>
    {% endblock %}
    """
    # crash.html (NEW GAME)
    crash_html_content = """
    {% extends "base.html" %}
    {% block title %}Crash{% endblock %}
    {% block content %}
    <div class="bg-gray-800 p-8 rounded-lg shadow-xl max-w-xl w-full mx-auto text-center border-2 border-gray-700">
        <h1 class="text-3xl font-bold mb-4 text-blue-400">
            📈 CRASH VIQUEIBET 📈
        </h1>
        <p class="text-gray-300 mb-6">
            Aposte e saque seus ganhos antes que o gráfico "caia"!
        </p>
        <p class="text-gray-400 text-sm mb-2">Usuário: {{ current_user.email }}</p>

        <div class="mb-6 p-3 bg-gray-700 rounded-md text-lg">
            <p>Seu Saldo:</p>
            <p class="text-green-400 text-2xl font-bold">R$ <span id="saldo-display">{{ saldo }}</span></p>
        </div>

        <div class="space-y-4 mb-6">
            <div>
                <label for="bet-amount" class="block text-lg font-semibold mb-2">Valor da Aposta (R$):</label>
                <input type="number" id="bet-amount" value="10" min="1" step="1"
                       class="w-full p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            <div>
                <label for="speed-factor" class="block text-lg font-semibold mb-2">Velocidade (1-5):</label>
                <input type="range" id="speed-factor" min="1" max="5" value="1" step="0.5"
                       class="w-full h-2 bg-gray-600 rounded-lg appearance-none cursor-pointer range-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                <span id="speed-value" class="text-sm text-gray-400">1.0x</span>
            </div>
            <button id="start-game-button" class="bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full">
                Iniciar Rodada
            </button>
        </div>

        <div id="game-area" class="relative bg-gray-700 p-4 rounded-lg mb-8" style="min-height: 250px;">
            <div id="multiplier-graph" class="mb-4">
                <div id="graph-line" style="transform: scaleX(0);"></div>
                <span id="current-multiplier-display">x1.00</span>
            </div>
            <p id="message-display" class="text-lg font-semibold text-white mt-4"></p>
            <button id="cash-out-button" class="bg-gradient-to-r from-yellow-500 to-orange-500 hover:from-yellow-600 hover:to-orange-600 text-gray-900 font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full mt-4" disabled>
                Sacar Ganhos
            </button>
        </div>

        <script>
            const saldoDisplay = document.getElementById('saldo-display');
            const betAmountInput = document.getElementById('bet-amount');
            const speedFactorInput = document.getElementById('speed-factor');
            const speedValueDisplay = document.getElementById('speed-value');
            const startGameButton = document.getElementById('start-game-button');
            const cashOutButton = document.getElementById('cash-out-button');
            const multiplierGraph = document.getElementById('multiplier-graph');
            const graphLine = document.getElementById('graph-line');
            const currentMultiplierDisplay = document.getElementById('current-multiplier-display');
            const messageDisplay = document.getElementById('message-display');

            let gameInterval;
            let currentMultiplier = 1.0;
            let crashPoint = 0;
            let isGameRunning = false;
            let hasCashedOut = false;

            speedFactorInput.addEventListener('input', () => {
                speedValueDisplay.textContent = parseFloat(speedFactorInput.value).toFixed(1) + 'x';
            });

            startGameButton.addEventListener('click', async () => {
                const betAmount = parseFloat(betAmountInput.value);
                const speedFactor = parseFloat(speedFactorInput.value);

                if (isNaN(betAmount) || betAmount <= 0) {
                    messageDisplay.textContent = "Aposta inválida!";
                    messageDisplay.classList.add('text-red-400');
                    return;
                }
                if (parseFloat(saldoDisplay.textContent.replace('R$', '').replace(',', '.')) < betAmount) {
                    messageDisplay.textContent = "Saldo insuficiente!";
                    messageDisplay.classList.add('text-red-400');
                    return;
                }

                startGameButton.disabled = true;
                betAmountInput.disabled = true;
                speedFactorInput.disabled = true;
                cashOutButton.disabled = false;
                messageDisplay.textContent = "Iniciando rodada...";
                messageDisplay.classList.remove('text-green-400', 'text-red-400');
                messageDisplay.classList.add('text-white');
                currentMultiplierDisplay.textContent = 'x1.00';
                multiplierGraph.classList.remove('crashed-effect');
                graphLine.style.transform = 'scaleX(0)'; // Reset graph line

                try {
                    const response = await fetch('/api/crash/start_game', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ bet_amount: betAmount, speed_factor: speedFactor })
                    });
                    const data = await response.json();

                    if (data.status === 'success') {
                        saldoDisplay.innerText = parseFloat(data.saldo).toFixed(2).replace('.', ',');
                        messageDisplay.textContent = data.message;
                        messageDisplay.classList.add('text-green-400');
                        crashPoint = parseFloat(data.crash_point);
                        isGameRunning = true;
                        hasCashedOut = false;
                        currentMultiplier = 1.0;
                        gameInterval = setInterval(updateGame, 100); // Update every 100ms
                    } else {
                        messageDisplay.textContent = data.message;
                        messageDisplay.classList.add('text-red-400');
                        startGameButton.disabled = false;
                        betAmountInput.disabled = false;
                        speedFactorInput.disabled = false;
                        cashOutButton.disabled = true;
                    }
                } catch (error) {
                    messageDisplay.textContent = "Erro de conexão ao iniciar jogo.";
                    messageDisplay.classList.add('text-red-400');
                    startGameButton.disabled = false;
                    betAmountInput.disabled = false;
                    speedFactorInput.disabled = false;
                    cashOutButton.disabled = true;
                }
            });

            async function updateGame() {
                if (!isGameRunning) return;

                try {
                    const response = await fetch('/api/crash/update_multiplier', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' }
                    });
                    const data = await response.json();

                    currentMultiplier = parseFloat(data.current_multiplier);
                    currentMultiplierDisplay.textContent = `x${currentMultiplier.toFixed(2)}`;
                    // Scale the graph line visually. Max multiplier can be high, so scale non-linearly
                    const visualScale = Math.min(1.0, currentMultiplier / 10.0); // Scale to 10 for visual, cap at 1
                    graphLine.style.transform = `scaleX(${visualScale})`;

                    if (data.is_crashed) {
                        clearInterval(gameInterval);
                        isGameRunning = false;
                        messageDisplay.textContent = data.message;
                        messageDisplay.classList.remove('text-green-400', 'text-white');
                        messageDisplay.classList.add('text-red-400');
                        multiplierGraph.classList.add('crashed-effect');
                        endGame();
                    } else {
                        messageDisplay.textContent = data.message;
                        messageDisplay.classList.remove('text-red-400');
                        messageDisplay.classList.add('text-green-400');
                    }
                    saldoDisplay.innerText = parseFloat(data.saldo).toFixed(2).replace('.', ','); // Update in case of backend changes
                } catch (error) {
                    clearInterval(gameInterval);
                    isGameRunning = false;
                    messageDisplay.textContent = "Erro de conexão durante o jogo. Rodada encerrada.";
                    messageDisplay.classList.add('text-red-400');
                    endGame();
                }
            }

            cashOutButton.addEventListener('click', async () => {
                if (!isGameRunning || hasCashedOut) return;

                clearInterval(gameInterval);
                isGameRunning = false;
                hasCashedOut = true;
                cashOutButton.disabled = true;
                messageDisplay.textContent = "Sacando...";
                messageDisplay.classList.remove('text-green-400', 'text-red-400');
                messageDisplay.classList.add('text-white');

                try {
                    const response = await fetch('/api/crash/cash_out', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' }
                    });
                    const data = await response.json();

                    saldoDisplay.innerText = parseFloat(data.saldo).toFixed(2).replace('.', ',');
                    messageDisplay.textContent = data.message;
                    messageDisplay.classList.remove('text-red-400', 'text-white');
                    messageDisplay.classList.add('text-green-400');
                    endGame();
                } catch (error) {
                    messageDisplay.textContent = "Erro de conexão ao sacar. Tente novamente.";
                    messageDisplay.classList.add('text-red-400');
                    endGame();
                }
            });

            function endGame() {
                startGameButton.disabled = false;
                betAmountInput.disabled = false;
                speedFactorInput.disabled = false;
                cashOutButton.disabled = true;
            }
        </script>
    </div>
    {% endblock %}
    """
    # fishing.html (NOVO JOGO)
    fishing_html_content = """
    {% extends "base.html" %}
    {% block title %}Jogo de Pesca{% endblock %}
    {% block content %}
    <div class="bg-gray-800 p-8 rounded-lg shadow-xl max-w-xl w-full mx-auto text-center border-2 border-gray-700">
        <h1 class="text-3xl font-bold mb-4 text-cyan-400">
            🎣 JOGO DE PESCA VIQUEIBET 🎣
        </h1>
        <p class="text-gray-300 mb-6">
            Jogue sua isca e tente pegar o peixe da sorte!
        </p>
        <p class="text-gray-400 text-sm mb-2">Usuário: {{ current_user.email }}</p>

        <div class="mb-6 p-3 bg-gray-700 rounded-md text-lg">
            <p>Seu Saldo:</p>
            <p class="text-green-400 text-2xl font-bold">R$ <span id="saldo-display">{{ saldo }}</span></p>
        </div>

        <div class="space-y-4 mb-6">
            <div>
                <label for="bet-amount" class="block text-lg font-semibold mb-2">Valor da Aposta (R$):</label>
                <input type="number" id="bet-amount" value="5" min="1" step="1"
                       class="w-full p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-cyan-500">
            </div>
            <button id="cast-line-button" class="bg-gradient-to-r from-blue-500 to-cyan-600 hover:from-blue-600 hover:to-cyan-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full">
                Lançar Isca!
            </button>
        </div>

        <div class="mb-8 p-4 bg-gray-700 rounded-lg">
            <p class="text-xl font-bold mb-2">Resultado da Pesca:</p>
            <p id="fishing-result-display" class="text-3xl font-extrabold text-white">?</p>
            <p id="winnings-display" class="text-lg font-semibold text-green-400 mt-2">Ganho: R$ 0.00</p>
        </div>

        <p id="message-display" class="text-lg font-semibold text-white"></p>

        <script>
            const saldoDisplay = document.getElementById('saldo-display');
            const betAmountInput = document.getElementById('bet-amount');
            const castLineButton = document.getElementById('cast-line-button');
            const fishingResultDisplay = document.getElementById('fishing-result-display');
            const winningsDisplay = document.getElementById('winnings-display');
            const messageDisplay = document.getElementById('message-display');

            castLineButton.addEventListener('click', async () => {
                const betAmount = parseFloat(betAmountInput.value);

                if (isNaN(betAmount) || betAmount <= 0) {
                    messageDisplay.textContent = "Aposta inválida!";
                    messageDisplay.classList.add('text-red-400');
                    return;
                }
                if (parseFloat(saldoDisplay.textContent.replace('R$', '').replace(',', '.')) < betAmount) {
                    messageDisplay.textContent = "Saldo insuficiente!";
                    messageDisplay.classList.add('text-red-400');
                    return;
                }

                castLineButton.disabled = true;
                messageDisplay.textContent = "Lançando a isca...";
                messageDisplay.classList.remove('text-green-400', 'text-red-400');
                messageDisplay.classList.add('text-white');
                fishingResultDisplay.textContent = "🎣...";
                winningsDisplay.textContent = "Ganho: R$ 0.00";

                try {
                    const response = await fetch('/api/fishing_game', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ aposta: betAmount })
                    });
                    const data = await response.json();

                    saldoDisplay.innerText = parseFloat(data.saldo).toFixed(2).replace('.', ',');
                    messageDisplay.textContent = data.message;
                    fishingResultDisplay.textContent = data.message;
                    winningsDisplay.textContent = `Ganho: R$ ${parseFloat(data.ganho).toFixed(2).replace('.', ',')}`;

                    if (parseFloat(data.ganho) > 0) {
                        messageDisplay.classList.add('text-green-400');
                        fishingResultDisplay.classList.add('text-green-400');
                        fishingResultDisplay.classList.remove('text-red-400');
                    } else {
                        messageDisplay.classList.add('text-red-400');
                        fishingResultDisplay.classList.add('text-red-400');
                        fishingResultDisplay.classList.remove('text-green-400');
                    }

                } catch (error) {
                    messageDisplay.textContent = "Erro de conexão ao pescar. Tente novamente.";
                    messageDisplay.classList.add('text-red-400');
                } finally {
                    castLineButton.disabled = false;
                }
            });
        </script>
    </div>
    {% endblock %}
    """
    # volcano.html (NOVO JOGO)
    volcano_html_content = """
    {% extends "base.html" %}
    {% block title %}Jogo do Vulcão{% endblock %}
    {% block content %}
    <div class="bg-gray-800 p-8 rounded-lg shadow-xl max-w-xl w-full mx-auto text-center border-2 border-gray-700">
        <h1 class="text-3xl font-bold mb-4 text-purple-400">
            🌋 JOGO DO VULCÃO VIQUEIBET 🌋
        </h1>
        <p class="text-gray-300 mb-6">
            Aposte em quão alto o multiplicador do vulcão vai chegar antes de "cair"!
        </p>
        <p class="text-gray-400 text-sm mb-2">Usuário: {{ current_user.email }}</p>

        <div class="mb-6 p-3 bg-gray-700 rounded-md text-lg">
            <p>Seu Saldo:</p>
            <p class="text-green-400 text-2xl font-bold">R$ <span id="saldo-display">{{ saldo }}</span></p>
        </div>

        <div class="space-y-4 mb-6">
            <div>
                <label for="bet-amount" class="block text-lg font-semibold mb-2">Valor da Aposta (R$):</label>
                <input type="number" id="bet-amount" value="10" min="1" step="1"
                       class="w-full p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500">
            </div>
            <div>
                <label for="bet-multiplier" class="block text-lg font-semibold mb-2">Apostar que o Multiplicador Atingirá (Ex: 2.5x):</label>
                <input type="number" id="bet-multiplier" value="2.0" min="1.1" max="10.0" step="0.1"
                       class="w-full p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600 focus:outline-none focus:ring-2 focus:ring-purple-500">
            </div>
            <button id="erupt-button" class="bg-gradient-to-r from-red-500 to-purple-600 hover:from-red-600 hover:to-purple-700 text-white font-bold py-3 px-6 rounded-lg shadow-lg transform hover:scale-105 transition duration-300 w-full">
                Fazer o Vulcão Entrar em Erupção!
            </button>
        </div>

        <div class="mb-8 p-4 bg-gray-700 rounded-lg">
            <p class="text-xl font-bold mb-2">Multiplicador da Erupção:</p>
            <p id="volcano-result-display" class="text-3xl font-extrabold text-white">x?</p>
            <p id="winnings-display" class="text-lg font-semibold text-green-400 mt-2">Ganho: R$ 0.00</p>
        </div>

        <p id="message-display" class="text-lg font-semibold text-white"></p>

        <script>
            const saldoDisplay = document.getElementById('saldo-display');
            const betAmountInput = document.getElementById('bet-amount');
            const betMultiplierInput = document.getElementById('bet-multiplier');
            const eruptButton = document.getElementById('erupt-button');
            const volcanoResultDisplay = document.getElementById('volcano-result-display');
            const winningsDisplay = document.getElementById('winnings-display');
            const messageDisplay = document.getElementById('message-display');

            eruptButton.addEventListener('click', async () => {
                const betAmount = parseFloat(betAmountInput.value);
                const betMultiplier = parseFloat(betMultiplierInput.value);

                if (isNaN(betAmount) || betAmount <= 0) {
                    messageDisplay.textContent = "Aposta inválida!";
                    messageDisplay.classList.add('text-red-400');
                    return;
                }
                if (isNaN(betMultiplier) || betMultiplier < 1.1 || betMultiplier > 10.0) {
                    messageDisplay.textContent = "Multiplicador de aposta inválido (1.1x - 10.0x)!";
                    messageDisplay.classList.add('text-red-400');
                    return;
                }
                if (parseFloat(saldoDisplay.textContent.replace('R$', '').replace(',', '.')) < betAmount) {
                    messageDisplay.textContent = "Saldo insuficiente!";
                    messageDisplay.classList.add('text-red-400');
                    return;
                }

                eruptButton.disabled = true;
                messageDisplay.textContent = "O vulcão está aquecendo...";
                messageDisplay.classList.remove('text-green-400', 'text-red-400');
                messageDisplay.classList.add('text-white');
                volcanoResultDisplay.textContent = "x?";
                winningsDisplay.textContent = "Ganho: R$ 0.00";

                try {
                    const response = await fetch('/api/volcano_game', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ aposta: betAmount, bet_multiplier: betMultiplier })
                    });
                    const data = await response.json();

                    saldoDisplay.innerText = parseFloat(data.saldo).toFixed(2).replace('.', ',');
                    messageDisplay.textContent = data.message;
                    volcanoResultDisplay.textContent = `x${parseFloat(data.result_multiplier).toFixed(2)}`;
                    winningsDisplay.textContent = `Ganho: R$ ${parseFloat(data.ganho).toFixed(2).replace('.', ',')}`;

                    if (parseFloat(data.ganho) > 0) {
                        messageDisplay.classList.add('text-green-400');
                        volcanoResultDisplay.classList.add('text-green-400');
                        volcanoResultDisplay.classList.remove('text-red-400');
                    } else {
                        messageDisplay.classList.add('text-red-400');
                        volcanoResultDisplay.classList.add('text-red-400');
                        volcanoResultDisplay.classList.remove('text-green-400');
                    }

                } catch (error) {
                    messageDisplay.textContent = "Erro de conexão com o vulcão. Tente novamente.";
                    messageDisplay.classList.add('text-red-400');
                } finally {
                    eruptButton.disabled = false;
                }
            });
        </script>
    </div>
    {% endblock %}
    """
    # admin.html
    admin_html_content = """
    {% extends "base.html" %}
    {% block title %}Dashboard Admin{% endblock %}
    {% block content %}
    <div class="bg-gray-800 p-8 rounded-lg shadow-xl max-w-4xl w-full mx-auto text-center border-2 border-gray-700">
        <h1 class="text-4xl font-bold mb-6 text-blue-500">
            <span class="text-yellow-400">⚙️</span> DASHBOARD ADMIN VIQUEIBET ⚙️
        </h1>
        <p class="text-gray-300 mb-4">
            Gerencie as contas de usuário e o sistema de depósito da ViqueiBET.
        </p>
        <p class="text-gray-400 text-sm mb-6">Administrador: {{ current_user.email }}</p>

        <!-- Seção de Controle de Usuários -->
        <h2 class="text-2xl font-semibold mb-4 text-gray-200">Controle de Usuários:</h2>
        <div class="space-y-4 mb-8 p-4 bg-gray-700 rounded-lg">
            <p class="text-lg font-semibold">Alterar Status Admin/Banimento:</p>
            <div>
                <label for="target-user-email" class="block text-left text-gray-300 text-sm font-semibold mb-1">E-mail do Usuário Alvo:</label>
                <input type="email" id="target-user-email" class="w-full p-2 rounded-md bg-gray-600 text-gray-100 border border-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="usuario@exemplo.com">
            </div>
            <div class="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2">
                <button id="make-admin-btn" class="flex-1 bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-3 rounded-md text-sm transition duration-150">Tornar Admin</button>
                <button id="remove-admin-btn" class="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-2 px-3 rounded-md text-sm transition duration-150">Remover Admin</button>
                <button id="ban-user-btn" class="flex-1 bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-3 rounded-md text-sm transition duration-150">Banir Usuário</button>
                <button id="unban-user-btn" class="flex-1 bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-3 rounded-md text-sm transition duration-150">Desbanir Usuário</button>
            </div>
            <p id="user-status-message" class="text-sm mt-2 font-semibold"></p>
        </div>

        <!-- Seção de Geração de Códigos de Depósito -->
        <h2 class="text-2xl font-semibold mb-4 text-gray-200">Gerar Códigos de Depósito:</h2>
        <div class="space-y-4 mb-8 p-4 bg-gray-700 rounded-lg">
            <div>
                <label for="code-amount" class="block text-left text-gray-300 text-sm font-semibold mb-1">Valor do Código (R$):</label>
                <input type="number" id="code-amount" value="50" min="10" step="1"
                       class="w-full p-2 rounded-md bg-gray-600 text-gray-100 border border-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            <div>
                <label for="num-codes" class="block text-left text-gray-300 text-sm font-semibold mb-1">Número de Códigos a Gerar:</label>
                <input type="number" id="num-codes" value="1" min="1" max="100" step="1"
                       class="w-full p-2 rounded-md bg-gray-600 text-gray-100 border border-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>
            <button id="generate-codes-btn" class="bg-yellow-600 hover:bg-yellow-700 text-white font-bold py-2 px-4 rounded-md text-sm transition duration-150 w-full">
                Gerar Códigos
            </button>
            <p id="generate-codes-message" class="text-sm mt-2 font-semibold"></p>
            
            <div id="generated-codes-list" class="mt-4 p-3 bg-gray-800 rounded-md max-h-48 overflow-y-auto" style="display: none;">
                <p class="font-bold text-lg mb-2 text-yellow-300">Códigos Gerados:</p>
                <ul class="list-disc list-inside text-gray-200" id="codes-ul">
                    <!-- Códigos serão inseridos aqui via JS -->
                </ul>
            </div>
        </div>


        <!-- Tabela de Visão Geral dos Usuários -->
        <h2 class="text-2xl font-semibold mb-4 text-gray-200">Visão Geral dos Usuários:</h2>
        
        <div class="overflow-x-auto relative shadow-md sm:rounded-lg mb-8">
            <table class="w-full text-sm text-left text-gray-400">
                <thead class="text-xs uppercase bg-gray-700 text-gray-400">
                    <tr>
                        <th scope="col" class="py-3 px-6">E-mail</th>
                        <th scope="col" class="py-3 px-6 text-right">Saldo</th>
                        <th scope="col" class="py-3 px-6">Cartão (Últ. 4 dígitos)</th>
                        <th scope="col" class="py-3 px-6">CPF/CNPJ (Masc.)</th>
                        <th scope="col" class="py-3 px-6">Admin Status</th>
                        <th scope="col" class="py-3 px-6">Ban Status</th>
                        <th scope="col" class="py-3 px-6">Gerenciar Saldo</th>
                        <th scope="col" class="py-3 px-6">Forçar Jogo</th>
                        <th scope="col" class="py-3 px-6">Ações</th> <!-- Nova coluna para deletar -->
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr class="bg-gray-800 border-b border-gray-700 hover:bg-gray-700">
                        <th scope="row" class="py-4 px-6 font-medium text-white whitespace-nowrap">{{ user.email }}</th>
                        <td class="py-4 px-6 text-right text-green-400 font-bold balance-display" data-user-email="{{ user.email }}">R$ {{ user.balance | round(2) }}</td>
                        <td class="py-4 px-6">{{ user.card_info.last_4 if user.card_info.last_4 else 'N/A' }}</td>
                        <td class="py-4 px-6">{{ user.personal_id.masked_value if user.personal_id.masked_value else 'N/A' }}</td>
                        <td class="py-4 px-6">
                            <span class="{{ 'status-admin' if user.is_admin else 'text-gray-400' }}">
                                {{ 'Sim' if user.is_admin else 'Não' }}
                            </span>
                        </td>
                        <td class="py-4 px-6">
                            <span class="{{ 'status-banned' if user.is_banned else 'text-gray-400' }}">
                                {{ 'Banido' if user.is_banned else 'Ativo' }}
                            </span>
                        </td>
                        <td class="py-4 px-6">
                            <div class="flex flex-col space-y-2">
                                <input type="number" step="0.01" min="0" value="100" class="balance-input w-full p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600">
                                <div class="flex space-x-2">
                                    <button class="add-balance-btn flex-1 bg-green-600 hover:bg-green-700 text-white font-bold py-1 px-2 rounded-md text-xs transition duration-150" data-user-email="{{ user.email }}">Adicionar</button>
                                    <button class="remove-balance-btn flex-1 bg-red-600 hover:bg-red-700 text-white font-bold py-1 px-2 rounded-md text-xs transition duration-150" data-user-email="{{ user.email }}">Remover</button>
                                </div>
                                <p class="balance-message text-xs mt-1"></p>
                            </div>
                        </td>
                        <td class="py-4 px-6">
                            <div class="flex flex-col space-y-2 text-center">
                                <select class="game-type-select p-2 rounded-md bg-gray-700 text-gray-100 border border-gray-600">
                                    <option value="none">Selecione Jogo</option>
                                    <option value="slots">Slots</option>
                                    <option value="roulette">Roleta</option>
                                    <option value="mines">Campo Minado</option>
                                    <option value="crash">Crash</option>
                                    <option value="fishing">Pesca</option>
                                    <option value="volcano">Vulcão</option>
                                </select>
                                <div class="flex space-x-2 mt-2">
                                    <button class="force-win-btn flex-1 bg-yellow-600 hover:bg-yellow-700 text-white font-bold py-1 px-2 rounded-md text-xs transition duration-150" data-user-email="{{ user.email }}">Forçar Vitória</button>
                                    <button class="force-lose-btn flex-1 bg-purple-600 hover:bg-purple-700 text-white font-bold py-1 px-2 rounded-md text-xs transition duration-150" data-user-email="{{ user.email }}">Forçar Derrota</button>
                                </div>
                                <button class="clear-force-btn bg-gray-500 hover:bg-gray-600 text-white font-bold py-1 px-2 rounded-md text-xs transition duration-150 mt-2" data-user-email="{{ user.email }}">Limpar Força</button>
                                <p class="force-message text-xs mt-1 text-yellow-300">{% if user.forced_game_outcome.game_type %}Forçado: {{ user.forced_game_outcome.game_type }} - {{ user.forced_game_outcome.outcome }}{% else %}N/A{% endif %}</p>
                            </div>
                        </td>
                        <td class="py-4 px-6">
                            {% if user.email != current_user.email %}
                            <button class="delete-user-btn bg-red-800 hover:bg-red-900 text-white font-bold py-2 px-4 rounded-md text-xs transition duration-150" data-user-email="{{ user.email }}">
                                Deletar
                            </button>
                            {% else %}
                            <span class="text-gray-500">N/A</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Tabela de Códigos de Depósito -->
        <h2 class="text-2xl font-semibold mb-4 text-gray-200">Códigos de Depósito Gerados:</h2>
        <div class="overflow-x-auto relative shadow-md sm:rounded-lg mb-8">
            <table class="w-full text-sm text-left text-gray-400">
                <thead class="text-xs uppercase bg-gray-700 text-gray-400">
                    <tr>
                        <th scope="col" class="py-3 px-6">Código</th>
                        <th scope="col" class="py-3 px-6 text-right">Valor</th>
                        <th scope="col" class="py-3 px-6">Usado?</th>
                        <th scope="col" class="py-3 px-6">Gerado Por</th>
                        <th scope="col" class="py-3 px-6">Gerado Em</th>
                        <th scope="col" class="py-3 px-6">Usado Por</th>
                        <th scope="col" class="py-3 px-6">Usado Em</th>
                    </tr>
                </thead>
                <tbody>
                    {% for code in deposit_codes %}
                    <tr class="bg-gray-800 border-b border-gray-700 hover:bg-gray-700">
                        <th scope="row" class="py-4 px-6 font-medium text-white whitespace-nowrap">{{ code.code }}</th>
                        <td class="py-4 px-6 text-right text-green-400 font-bold">R$ {{ code.amount | round(2) }}</td>
                        <td class="py-4 px-6">
                            <span class="{{ 'text-red-400' if code.is_used else 'text-green-400' }}">
                                {{ 'Sim' if code.is_used else 'Não' }}
                            </span>
                        </td>
                        <td class="py-4 px-6">{{ code.generated_by }}</td>
                        <td class="py-4 px-6">{{ code.generated_at.split('T')[0] if code.generated_at else 'N/A' }}</td>
                        <td class="py-4 px-6">{{ code.used_by if code.used_by else 'N/A' }}</td>
                        <td class="py-4 px-6">{{ code.used_at.split('T')[0] if code.used_at else 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>


        <script>
            // --- Gerenciamento de Saldo ---
            document.querySelectorAll('.add-balance-btn').forEach(button => {
                button.addEventListener('click', async (event) => {
                    const userEmail = event.target.dataset.userEmail;
                    const row = event.target.closest('tr');
                    const input = row.querySelector('.balance-input');
                    const messageElement = row.querySelector('.balance-message');
                    const balanceDisplay = row.querySelector('.balance-display');
                    const amount = parseFloat(input.value);

                    if (isNaN(amount) || amount <= 0) {
                        messageElement.textContent = "Valor inválido.";
                        messageElement.classList.remove('text-green-400');
                        messageElement.classList.add('text-red-400');
                        return;
                    }

                    messageElement.textContent = "Processando...";
                    messageElement.classList.remove('text-green-400', 'text-red-400');
                    messageElement.classList.add('text-white');
                    
                    try {
                        const response = await fetch('/api/admin/update_balance', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ email: userEmail, amount: amount, action: 'add' })
                        });
                        const data = await response.json();

                        if (data.status === 'success') {
                            messageElement.textContent = data.message;
                            messageElement.classList.remove('text-red-400', 'text-white');
                            messageElement.classList.add('text-green-400');
                            balanceDisplay.textContent = 'R$ ' + parseFloat(data.new_balance).toFixed(2).replace('.', ',');
                        } else {
                            messageElement.textContent = data.message;
                            messageElement.classList.remove('text-green-400', 'text-white');
                            messageElement.classList.add('text-red-400');
                        }
                    } catch (error) {
                        messageElement.textContent = "Erro de rede. Tente novamente.";
                        messageElement.classList.add('text-red-400');
                    }
                });
            });

            document.querySelectorAll('.remove-balance-btn').forEach(button => {
                button.addEventListener('click', async (event) => {
                    const userEmail = event.target.dataset.userEmail;
                    const row = event.target.closest('tr');
                    const input = row.querySelector('.balance-input');
                    const messageElement = row.querySelector('.balance-message');
                    const balanceDisplay = row.querySelector('.balance-display');
                    const amount = parseFloat(input.value);

                    if (isNaN(amount) || amount <= 0) {
                        messageElement.textContent = "Valor inválido.";
                        messageElement.classList.remove('text-green-400');
                        messageElement.classList.add('text-red-400');
                        return;
                    }
                    
                    messageElement.textContent = "Processando...";
                    messageElement.classList.remove('text-green-400', 'text-red-400');
                    messageElement.classList.add('text-white');

                    try {
                        const response = await fetch('/api/admin/update_balance', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ email: userEmail, amount: amount, action: 'remove' })
                        });
                        const data = await response.json();

                        if (data.status === 'success') {
                            messageElement.textContent = data.message;
                            messageElement.classList.remove('text-red-400', 'text-white');
                            messageElement.classList.add('text-green-400');
                            balanceDisplay.textContent = 'R$ ' + parseFloat(data.new_balance).toFixed(2).replace('.', ',');
                        } else {
                            messageElement.textContent = data.message;
                            messageElement.classList.remove('text-green-400', 'text-white');
                            messageElement.classList.add('text-red-400');
                        }
                    } catch (error) {
                        messageElement.textContent = "Erro de rede. Tente novamente.";
                        messageElement.classList.add('text-red-400');
                    }
                });
            });

            // --- Forçar Resultado de Jogo ---
            document.querySelectorAll('.force-win-btn').forEach(button => {
                button.addEventListener('click', async (event) => {
                    const userEmail = event.target.dataset.userEmail;
                    const row = event.target.closest('tr');
                    const gameTypeSelect = row.querySelector('.game-type-select');
                    const forceMessageElement = row.querySelector('.force-message');
                    const gameType = gameTypeSelect.value;

                    if (gameType === 'none') {
                        forceMessageElement.textContent = "Selecione um jogo!";
                        forceMessageElement.classList.remove('text-green-400');
                        forceMessageElement.classList.add('text-red-400');
                        return;
                    }

                    forceMessageElement.textContent = "Aplicando...";
                    forceMessageElement.classList.remove('text-green-400', 'text-red-400');
                    forceMessageElement.classList.add('text-white');

                    try {
                        const response = await fetch('/api/admin/force_outcome', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email: userEmail, game_type: gameType, outcome: 'win' })
                        });
                        const data = await response.json();
                        forceMessageElement.textContent = data.message;
                        if (data.status === 'success') {
                            forceMessageElement.classList.remove('text-red-400', 'text-white');
                            forceMessageElement.classList.add('text-green-400');
                        } else {
                            forceMessageElement.classList.remove('text-green-400', 'text-white');
                            forceMessageElement.classList.add('text-red-400');
                        }
                    } catch (error) {
                        forceMessageElement.textContent = "Erro de rede ao forçar.";
                        forceMessageElement.classList.add('text-red-400');
                    }
                });
            });

            document.querySelectorAll('.force-lose-btn').forEach(button => {
                button.addEventListener('click', async (event) => {
                    const userEmail = event.target.dataset.userEmail;
                    const row = event.target.closest('tr');
                    const gameTypeSelect = row.querySelector('.game-type-select');
                    const forceMessageElement = row.querySelector('.force-message');
                    const gameType = gameTypeSelect.value;

                    if (gameType === 'none') {
                        forceMessageElement.textContent = "Selecione um jogo!";
                        forceMessageElement.classList.remove('text-green-400');
                        forceMessageElement.classList.add('text-red-400');
                        return;
                    }

                    forceMessageElement.textContent = "Aplicando...";
                    forceMessageElement.classList.remove('text-green-400', 'text-red-400');
                    forceMessageElement.classList.add('text-white');

                    try {
                        const response = await fetch('/api/admin/force_outcome', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email: userEmail, game_type: gameType, outcome: 'lose' })
                        });
                        const data = await response.json();
                        forceMessageElement.textContent = data.message;
                        if (data.status === 'success') {
                            forceMessageElement.classList.remove('text-red-400', 'text-white');
                            forceMessageElement.classList.add('text-green-400');
                        } else {
                            forceMessageElement.classList.remove('text-green-400', 'text-white');
                            forceMessageElement.classList.add('text-red-400');
                        }
                    } catch (error) {
                        forceMessageElement.textContent = "Erro de rede ao forçar.";
                        forceMessageElement.classList.add('text-red-400');
                    }
                });
            });

            document.querySelectorAll('.clear-force-btn').forEach(button => {
                button.addEventListener('click', async (event) => {
                    const userEmail = event.target.dataset.userEmail;
                    const row = event.target.closest('tr');
                    const forceMessageElement = row.querySelector('.force-message');
                    const gameTypeSelect = row.querySelector('.game-type-select');
                    
                    forceMessageElement.textContent = "Limpando...";
                    forceMessageElement.classList.remove('text-green-400', 'text-red-400');
                    forceMessageElement.classList.add('text-white');

                    try {
                        const response = await fetch('/api/admin/force_outcome', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ email: userEmail, outcome: 'clear' })
                        });
                        const data = await response.json();
                        forceMessageElement.textContent = data.message;
                        if (data.status === 'success') {
                            forceMessageElement.classList.remove('text-red-400', 'text-white');
                            forceMessageElement.classList.add('text-green-400');
                            gameTypeSelect.value = 'none'; // Reset select
                        } else {
                            forceMessageElement.classList.remove('text-green-400', 'text-white');
                            forceMessageElement.classList.add('text-red-400');
                        }
                    } catch (error) {
                        forceMessageElement.textContent = "Erro de rede ao limpar.";
                        forceMessageElement.classList.add('text-red-400');
                    }
                });
            });

            // --- Gerenciamento de Admin/Banimento ---
            const targetUserEmailInput = document.getElementById('target-user-email');
            const makeAdminBtn = document.getElementById('make-admin-btn');
            const removeAdminBtn = document.getElementById('remove-admin-btn');
            const banUserBtn = document.getElementById('ban-user-btn');
            const unbanUserBtn = document.getElementById('unban-user-btn');
            const userStatusMessage = document.getElementById('user-status-message');

            async function updateUserAdminStatus(email, isAdmin) {
                userStatusMessage.textContent = "Atualizando status...";
                userStatusMessage.classList.remove('text-green-400', 'text-red-400');
                userStatusMessage.classList.add('text-white');

                try {
                    const response = await fetch('/api/admin/set_admin_status', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email: email, is_admin: isAdmin })
                    });
                    const data = await response.json();
                    userStatusMessage.textContent = data.message;
                    if (data.status === 'success') {
                        userStatusMessage.classList.remove('text-red-400', 'text-white');
                        userStatusMessage.classList.add('text-green-400');
                        // Refresh table data
                        location.reload(); 
                    } else {
                        userStatusMessage.classList.remove('text-green-400', 'text-white');
                        userStatusMessage.classList.add('text-red-400');
                    }
                } catch (error) {
                    userStatusMessage.textContent = "Erro de rede ao atualizar status de admin.";
                    userStatusMessage.classList.add('text-red-400');
                }
            }

            async function updateUserBanStatus(email, isBanned) {
                userStatusMessage.textContent = "Atualizando status de banimento...";
                userStatusMessage.classList.remove('text-green-400', 'text-red-400');
                userStatusMessage.classList.add('text-white');

                try {
                    const response = await fetch('/api/admin/ban_user', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ email: email, is_banned: isBanned })
                    });
                    const data = await response.json();
                    userStatusMessage.textContent = data.message;
                    if (data.status === 'success') {
                        userStatusMessage.classList.remove('text-red-400', 'text-white');
                        userStatusMessage.classList.add('text-green-400');
                        // Refresh table data
                        location.reload();
                    } else {
                        userStatusMessage.classList.remove('text-green-400', 'text-white');
                        userStatusMessage.classList.add('text-red-400');
                    }
                } catch (error) {
                    userStatusMessage.textContent = "Erro de rede ao atualizar status de banimento.";
                    userStatusMessage.classList.add('text-red-400');
                }
            }

            makeAdminBtn.addEventListener('click', () => {
                const email = targetUserEmailInput.value;
                if (email) {
                    updateUserAdminStatus(email, true);
                } else {
                    userStatusMessage.textContent = "Por favor, insira um e-mail.";
                    userStatusMessage.classList.add('text-red-400');
                }
            });

            removeAdminBtn.addEventListener('click', () => {
                const email = targetUserEmailInput.value;
                if (email) {
                    updateUserAdminStatus(email, false);
                } else {
                    userStatusMessage.textContent = "Por favor, insira um e-mail.";
                    userStatusMessage.classList.add('text-red-400');
                }
            });

            banUserBtn.addEventListener('click', () => {
                const email = targetUserEmailInput.value;
                if (email) {
                    updateUserBanStatus(email, true);
                } else {
                    userStatusMessage.textContent = "Por favor, insira um e-mail.";
                    userStatusMessage.classList.add('text-red-400');
                }
            });

            unbanUserBtn.addEventListener('click', () => {
                const email = targetUserEmailInput.value;
                if (email) {
                    updateUserBanStatus(email, false);
                } else {
                    userStatusMessage.textContent = "Por favor, insira um e-mail.";
                    userStatusMessage.classList.add('text-red-400');
                }
            });

            // --- Gerar Códigos de Depósito ---
            const codeAmountInput = document.getElementById('code-amount');
            const numCodesInput = document.getElementById('num-codes');
            const generateCodesBtn = document.getElementById('generate-codes-btn');
            const generateCodesMessage = document.getElementById('generate-codes-message');
            const generatedCodesList = document.getElementById('generated-codes-list');
            const codesUl = document.getElementById('codes-ul');

            generateCodesBtn.addEventListener('click', async () => {
                const amount = parseFloat(codeAmountInput.value);
                const numCodes = parseInt(numCodesInput.value);

                if (isNaN(amount) || amount <= 0 || isNaN(numCodes) || numCodes <= 0) {
                    generateCodesMessage.textContent = "Valor ou número de códigos inválido.";
                    generateCodesMessage.classList.remove('text-green-400');
                    generateCodesMessage.classList.add('text-red-400');
                    return;
                }

                generateCodesBtn.disabled = true;
                generateCodesMessage.textContent = "Gerando códigos...";
                generateCodesMessage.classList.remove('text-green-400', 'text-red-400');
                generateCodesMessage.classList.add('text-white');

                try {
                    const response = await fetch('/api/admin/generate_deposit_code', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ amount: amount, num_codes: numCodes })
                    });
                    const data = await response.json();

                    generateCodesMessage.textContent = data.message;
                    if (data.status === 'success') {
                        generateCodesMessage.classList.remove('text-red-400', 'text-white');
                        generateCodesMessage.classList.add('text-green-400');
                        generatedCodesList.style.display = 'block';
                        
                        // Clear existing codes and add new ones
                        codesUl.innerHTML = ''; 
                        data.generated_codes.forEach(codeInfo => {
                            const li = document.createElement('li');
                            li.textContent = `Código: ${codeInfo.code} (R$ ${parseFloat(codeInfo.amount).toFixed(2).replace('.', ',')})`;
                            codesUl.appendChild(li);
                        });
                        location.reload(); // Recarregar a página para atualizar a tabela de códigos
                    } else {
                        generateCodesMessage.classList.remove('text-green-400', 'text-white');
                        generateCodesMessage.classList.add('text-red-400');
                    }
                } catch (error) {
                    generateCodesMessage.textContent = "Erro de rede ao gerar códigos.";
                    generateCodesMessage.classList.add('text-red-400');
                } finally {
                    generateCodesBtn.disabled = false;
                }
            });

            // --- Deletar Usuário ---
            document.querySelectorAll('.delete-user-btn').forEach(button => {
                button.addEventListener('click', async (event) => {
                    const userEmail = event.target.dataset.userEmail;
                    const confirmDelete = confirm(`Tem certeza que deseja DELETAR o usuário ${userEmail}? Esta ação é irreversível.`);
                    
                    if (confirmDelete) {
                        try {
                            const response = await fetch('/api/admin/delete_user', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ email: userEmail })
                            });
                            const data = await response.json();

                            const messageElement = event.target.closest('td').querySelector('.delete-message') || 
                                document.createElement('p');
                            if (!messageElement.classList.contains('delete-message')) {
                                messageElement.classList.add('delete-message', 'text-xs', 'mt-1', 'font-semibold');
                                event.target.closest('td').appendChild(messageElement);
                            }

                            messageElement.textContent = data.message;
                            if (data.status === 'success') {
                                messageElement.classList.remove('text-red-400');
                                messageElement.classList.add('text-green-400');
                                // Remove the row from the table on successful deletion
                                event.target.closest('tr').remove();
                            } else {
                                messageElement.classList.remove('text-green-400');
                                messageElement.classList.add('text-red-400');
                            }
                        } catch (error) {
                            alert("Erro de conexão ao deletar usuário."); // Usando alert temporariamente para erro crítico de rede
                            console.error("Erro ao deletar usuário:", error);
                        }
                    }
                });
            });

        </script>
    </div>
    {% endblock %}
    """

    # Cria os arquivos .html
    with open(os.path.join('templates', 'base.html'), 'w', encoding='utf-8') as f:
        f.write(base_html_content)
    with open(os.path.join('templates', 'login.html'), 'w', encoding='utf-8') as f:
        f.write(login_html_content)
    with open(os.path.join('templates', 'register.html'), 'w', encoding='utf-8') as f:
        f.write(register_html_content)
    with open(os.path.join('templates', 'deposit.html'), 'w', encoding='utf-8') as f:
        f.write(deposit_html_content)
    with open(os.path.join('templates', 'index.html'), 'w', encoding='utf-8') as f:
        f.write(index_html_content)
    with open(os.path.join('templates', 'slots.html'), 'w', encoding='utf-8') as f:
        f.write(slots_html_content)
    with open(os.path.join('templates', 'roulette.html'), 'w', encoding='utf-8') as f:
        f.write(roulette_html_content)
    with open(os.path.join('templates', 'auto_roulette.html'), 'w', encoding='utf-8') as f:
        f.write(auto_roulette_html_content)
    with open(os.path.join('templates', 'mines.html'), 'w', encoding='utf-8') as f:
        f.write(mines_html_content)
    with open(os.path.join('templates', 'crash.html'), 'w', encoding='utf-8') as f:
        f.write(crash_html_content)
    with open(os.path.join('templates', 'fishing.html'), 'w', encoding='utf-8') as f:
        f.write(fishing_html_content)
    with open(os.path.join('templates', 'volcano.html'), 'w', encoding='utf-8') as f:
        f.write(volcano_html_content)
    with open(os.path.join('templates', 'admin.html'), 'w', encoding='utf-8') as f:
        f.write(admin_html_content)


    print("Arquivos HTML criados/atualizados na pasta 'templates/'.")
    print("\nPara rodar o aplicativo, abra seu terminal na pasta onde 'app.py' está e digite:")
    print("flask run")
    print("\nEntão, abra seu navegador e acesse: http://127.0.0.1:5000/")
    print("\n--- CREDENCIAIS ADMIN ---")
    print(f"Email: {ADMIN_EMAIL}")
    print(f"Senha: {ADMIN_PASSWORD}")
    print("--------------------------")
    app.run(host='0.0.0.0', port=5000)
