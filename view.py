from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re
import fdb
from datetime import datetime, timedelta
from main import app, con

app = Flask(__name__)
CORS(app, origins=["*"])

app.config.from_pyfile('config.py')
senha_secreta = app.config['SECRET_KEY']

def generate_token(user_id, email):
    payload = {'id_usuario': user_id, 'email':email}
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
    if not request.is_json:
        return jsonify({"error": "É necessário enviar JSON válido"}), 400

    data = request.get_json()

    if not data:
        return jsonify({"error": "JSON vazio"}), 400

    campos = ['nome', 'email', 'telefone', 'senha', 'categoria', 'tipo']
    faltando = [campo for campo in campos if not data.get(campo)]
    if faltando:
        return jsonify({"error": f"Campos obrigatórios faltando: {', '.join(faltando)}"}), 400

    nome = data['nome']
    email = data['email']
    telefone = data['telefone']
    senha = data['senha']
    categoria = data['categoria']
    tipo = data['tipo']

    senha_check = validar_senha(senha)
    if senha_check is not True:
        return senha_check

    cur = con.cursor()

    cur.execute("SELECT 1 FROM cadastro WHERE email = ?", (email,))
    if cur.fetchone():
        cur.close()
        return jsonify({"error": "Este usuário já foi cadastrado!"}), 400

    senha_hashed = generate_password_hash(senha)

    cur.execute(
        "INSERT INTO CADASTRO (NOME, EMAIL, TELEFONE, SENHA, CATEGORIA, TIPO, ATIVO) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (nome, email, telefone, senha_hashed, categoria, tipo, True)
    )
    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuário cadastrado com sucesso!",
        'usuario': {
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
        return jsonify({"error": "Todos os campos são obrigatórios"}), 400

    # Simulando busca no banco
    cur = con.cursor()
    cur.execute("SELECT senha, tipo, id_cadastro, ativo, nome, telefone FROM CADASTRO WHERE email = ?", (email,))
    usuario = cur.fetchone()
    cur.close()

    if not usuario:
        return jsonify({"error": "Usuário ou senha inválidos"}), 401

    senha_armazenada, tipo, id_cadastro, ativo, nome, telefone = usuario

    if not ativo:
        return jsonify({"error": "Usuário inativo"}), 401

    if check_password_hash(senha_armazenada, senha):
        # Login OK, gera token
        token = generate_token(id_cadastro, email)
        return jsonify({
            "message": "Login realizado com sucesso!",
            "usuario": {
                "id_cadastro": id_cadastro,
                "nome": nome,
                "email": email,
                "telefone": telefone,
                "tipo": tipo,
                "token": token
            }
        })

    else:
        # Controle de tentativas
        if id_cadastro not in tentativas:
            tentativas[id_cadastro] = 0

        if tipo != 'adm':
            tentativas[id_cadastro] += 1
            if tentativas[id_cadastro] >= 3:
                cur = con.cursor()
                cur.execute("UPDATE CADASTRO SET ATIVO = false WHERE id_cadastro = ?", (id_cadastro,))
                con.commit()
                cur.close()
                return jsonify({"error": "Usuário inativado por excesso de tentativas."}), 403

        return jsonify({"error": "Senha incorreta"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')

    if not token:
        return jsonify({"error": "Token de autenticação necessário"}), 401

    token = remover_bearer(token)

    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])

        return jsonify({"message": "Logout realizado com sucesso!"}), 200

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

codigos_temp = {}

@app.route('/servicos', methods=['POST'])
def cadastrar_servico():
    try:
        data = request.get_json()

        id_profissional = data.get('id_profissional')
        descricao = data.get('descricao')
        duracao = data.get('duracao')
        preco = data.get('preco')
        data_servico = data.get('data')
        horario_inicio = data.get('horario')

        if not all([id_profissional, descricao, duracao, preco, data_servico, horario_inicio]):
            return jsonify({"error": "Todos os campos são obrigatórios"}), 400

        cur = con.cursor()

        cur.execute("""
            SELECT horario, duracao 
            FROM servicos 
            WHERE id_profissional = :id_profissional AND data = :data_servico
        """, {"id_profissional": id_profissional, "data_servico": data_servico})

        servicos_existentes = cur.fetchall()

        novo_inicio = datetime.strptime(f"{data_servico} {horario_inicio}", "%Y-%m-%d %H:%M")
        novo_fim = novo_inicio + timedelta(minutes=int(duracao))

        for serv in servicos_existentes:
            existente_inicio = datetime.strptime(f"{data_servico} {serv[0]}", "%Y-%m-%d %H:%M")
            existente_fim = existente_inicio + timedelta(minutes=int(serv[1]))

            if (novo_inicio < existente_fim) and (novo_fim > existente_inicio):
                cur.close()
                return jsonify({"error": "Serviço conflita com outro já agendado"}), 400

        cur.execute("""
            INSERT INTO servicos (id_profissional, descricao, duracao, preco, data, horario)
            VALUES (:id_profissional, :descricao, :duracao, :preco, :data_servico, :horario_inicio)
        """, {
            "id_profissional": id_profissional,
            "descricao": descricao,
            "duracao": duracao,
            "preco": preco,
            "data_servico": data_servico,
            "horario_inicio": horario_inicio
        })

        con.commit()
        cur.close()

        return jsonify({"message": "Serviço cadastrado com sucesso!"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/servicos', methods=['GET'])
def listar_servicos():
    cur = con.cursor()
    # Seleciona todos os campos da tabela, incluindo data e horário
    cur.execute("SELECT id_servico, id_profissional, descricao, duracao, preco, data_servico, horario FROM servicos")
    servicos = cur.fetchall()
    cur.close()

    lista = []
    for servico in servicos:
        lista.append({
            'id_servico': servico[0],
            'id_profissional': servico[1],
            'descricao': servico[2],
            'duracao': servico[3],
            'preco': float(servico[4]),
            'data_servico': servico[5].strftime('%Y-%m-%d') if servico[5] else None,
            'horario': servico[6].strftime('%H:%M') if servico[6] else None
        })

    return jsonify({
        'mensagem': 'Lista de serviços',
        'servicos': lista
    }), 200


@app.route('/servicos/<int:id>', methods=['PUT'])
def editar_servico(id):
    data = request.get_json()

    id_profissional = data.get('id_profissional')
    descricao = data.get('descricao')
    duracao = data.get('duracao')
    preco = data.get('preco')

    cur = con.cursor()

    cur.execute("SELECT id_servico FROM servicos WHERE id_servico = ?", (id,))
    if not cur.fetchone():
        cur.close()
        return jsonify({"error": "Serviço não encontrado"}), 404

    cur.execute("""
        UPDATE servicos
        SET id_profissional = ?, descricao = ?, duracao = ?, preco = ?
        WHERE id_servico = ?
    """, (id_profissional, descricao, duracao, preco, id))

    con.commit()
    cur.close()

    return jsonify({
        "message": "Serviço atualizado com sucesso!",
        "servico": {
            "id_servico": id,
            "id_profissional": id_profissional,
            "descricao": descricao,
            "duracao": duracao,
            "preco": float(preco)
        }
    }), 200

