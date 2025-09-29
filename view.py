from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re
import fdb
from main import app, con

app = Flask(__name__)
CORS(app, origins=["*"])

app.config.from_pyfile('config.py')
senha_secreta = app.config['SECRET_KEY']

def generate_token(user_id, email):
    payload = {'id_cadastro': user_id, 'email':email}
    token = jwt.encode(payload, senha_secreta, algorithm='HS256')
    return token

def remover_bearer(token):
    if token.startswith('Bearer '):
        return token[len('Bearer '):]
    else:
        return token

def validar_senha(senha):
    if len(senha) < 8:
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres"}), 400

    if not re.search(r"[!@#$%¨&*(),.?\":<>{}|]", senha):
        return jsonify({"error": "A senha deve conter pelo menos um símbolo especial"}), 400

    if not re.search(r"[A-Z]", senha):
        return jsonify({"error": "A senha deve conter pelo menos uma letra maiúscula"}), 400

    if len(re.findall(r"\d", senha)) < 2:
        return jsonify({"error": "A senha deve conter pelo menos dois números"}), 400

    return True

def verificar_adm(id_cadastro):
    cur = con.cursor()
    cur.execute("SELECT tipo FROM cadastro WHERE id_cadastro = ?", (id_cadastro,))
    tipo = cur.fetchone()

    if tipo and tipo[0] == 'adm':
        return True
    else:
        return False

@app.route('/cadastro', methods=['POST'])
def cadastro_usuario():
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    telefone = data.get('telefone')
    senha = data.get('senha')
    categoria = data.get('categoria')
    tipo = data.get('tipo')

    senha_check = validar_senha(senha)
    if senha_check is not True:
        return senha_check

    cur = con.cursor()
    cur.execute("SELECT 1 FROM cadastro WHERE email = ?", (email,))

    if cur.fetchone():
        return jsonify({"error": "Este usuário já foi cadastrado!"}), 400

    senha = generate_password_hash(senha)

    cur.execute(
        "INSERT INTO CADASTRO (NOME, EMAIL, TELEFONE, SENHA, CATEGORIA, TIPO, ATIVO) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (nome, email, telefone, senha, categoria, tipo, True)
    )

    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuário cadastrado!",
        'usuarios': {
            'nome': nome,
            'email': email,
            'tipo': tipo
        }
    }), 200

@app.route('/cadastro', methods=['GET'])
def lista_cadastro():
        cur = con.cursor()
        cur.execute("SELECT id_cadastro, nome, email, telefone, senha, categoria, tipo, ativo FROM cadastro")
        usuarios = cur.fetchall()
        usuarios_dic = []

        for usuario in usuarios:
            usuarios_dic.append({
            'id_cadastro': usuario[0],
            'nome': usuario[1],
            'email': usuario[2],
            'telefone': usuario[3],
            'senha': usuario[4],
            'categoria': usuario[5],
            'tipo': usuario[6]
            })

        return jsonify(mensagem='Lista de usuarios', usuarios=usuarios_dic)

@app.route('/cadastro/<int:id>', methods=['DELETE'])
def deletar_Usuario(id):
    cur = con.cursor()

    cur.execute("SELECT 1 FROM cadastro WHERE id_cadastro = ?", (id,))
    if not cur.fetchone():
        cur.close()
        return jsonify({"error": "Usuario não encontrado"}), 404

    cur.execute("DELETE FROM cadastro WHERE id_cadastro = ?", (id,))
    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuario excluído com sucesso!",
        'id_cadastro': id
    })

@app.route('/cadastro/<int:id>', methods=['PUT'])
def editar_usuario(id):
    cur = con.cursor()
    cur.execute("SELECT id_cadastro, nome, email, telefone, senha, categoria, tipo, ativo FROM CADASTRO WHERE id_cadastro = ?", (id,))
    usuarios_data = cur.fetchone()

    if not usuarios_data:
        cur.close()
        return jsonify({"error": "Usuário não foi encontrado"}), 404

    email_armazenado = usuarios_data[2]
    tipo_armazenado = usuarios_data[6]
    ativo_armazenado = usuarios_data[7]

    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    telefone = data.get('telefone')
    senha = data.get('senha')
    categoria = data.get('categoria')
    tipo = data.get('tipo')
    ativo = data.get('ativo')

    # validação de senha
    if senha is not None:
        senha_check = validar_senha(senha)
        if senha_check is not True:
            return senha_check
        senha = generate_password_hash(senha)
    else:
        senha = usuarios_data[4]  # mantém a senha antiga

    if tipo is None:
        tipo = tipo_armazenado
    if ativo is None:
        ativo = ativo_armazenado

    if email_armazenado != email:
        cur.execute("SELECT 1 FROM cadastro WHERE email = ?", (email,))
        if cur.fetchone():
            cur.close()
            return jsonify({"message": "Este usuário já foi cadastrado!"}), 400

    cur.execute(
        "UPDATE cadastro SET nome = ?, email = ?, telefone = ?, senha = ?, categoria = ?, tipo = ?, ativo = ? WHERE id_cadastro = ?",
        (nome, email, telefone, senha, categoria, tipo, ativo, id)
    )

    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuário atualizado com sucesso!",
        'usuarios': {
            'nome': nome,
            'email': email,
            'telefone': telefone,
            'categoria': categoria,
            'tipo': tipo,
            'ativo': ativo
        }
    })

tentativas = {}
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    if not email or not senha:
        return jsonify({"error": "Todos os campos (email, senha) são obrigatórios."}), 400

    cur = con.cursor()
    cur.execute("SELECT senha, tipo, id_cadastro, ativo, nome, telefone, email FROM CADASTRO WHERE EMAIL = ?", (email,))
    usuario = cur.fetchone()

    if not usuario:
        cur.close()
        return jsonify({"error": "Usuário ou senha inválidos."}), 401

    senha_armazenada = usuario[0]
    tipo = usuario[1]
    id_cadastro = usuario[2]
    ativo = usuario[3]
    nome = usuario[4]
    telefone = usuario[5]

    # Inicializa tentativas para o usuário se não existir
    if id_cadastro not in tentativas:
        tentativas[id_cadastro] = 0

    if not ativo:
        cur.close()
        return jsonify({"error": "Usuário inativo."}), 401

    # Verifica a senha
    if check_password_hash(senha_armazenada, senha):
        # Reseta tentativas se login for bem-sucedido
        tentativas[id_cadastro] = 0
        token = generate_token(id_cadastro, email)
        cur.close()
        return jsonify({
            'message': "Login realizado com sucesso!",
            'usuarios': {
                'nome': nome,
                'telefone': telefone,
                'email': email,
                'id_cadastro': id_cadastro,
                'tipo': tipo,
                'token': token
            }
        })

    else:
        # Incrementa tentativas apenas se não for admin
        if tipo != 'adm':
            tentativas[id_cadastro] += 1
            if tentativas[id_cadastro] >= 3:
                cur.execute("UPDATE CADASTRO SET ATIVO = false WHERE id_cadastro = ?", (id_cadastro,))
                con.commit()
                cur.close()
                return jsonify({"error": "Usuário inativado por excesso de tentativas."}), 403

        cur.close()
        return jsonify({"error": "Senha incorreta."}), 401

@app.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"error": "Token de autenticação necessário"}), 401

    # Remove o 'Bearer' se presente no toke
    token = remover_bearer(token)

    try:
        #  validar sua assinatura e verificar a validade
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        # "removendo" o token no cliente.
        return jsonify({"message": "Logout realizado com sucesso!"}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401
codigos_temp = {}


@app.route("/servicos", methods=["POST"])
def cadastrar_servico():
    data = request.json

    # conexão direta com Firebird
    con = fdb.connect(
        dsn='localhost:C:/caminho/do/seubanco.fdb',
        user='SYSDBA',
        password='masterkey',
        charset='UTF8'
    )
    cur = con.cursor()

    # insert
    cur.execute("""
        INSERT INTO servicos (id_profissional, nome, categoria, duracao, preco)
        VALUES (?, ?, ?, ?, ?)
    """, (
        data["id_profissional"],
        data["nome"],
        data["categoria"],
        data["duracao"],
        data["preco"]
    ))

    con.commit()
    con.close()

    return jsonify({"message": "Serviço cadastrado com sucesso!"})
