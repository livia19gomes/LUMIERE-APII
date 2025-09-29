import fdb
class Cadastro:
    def __init__(self, id_cadastro, nome, email, telefone, senha, categoria, ativo):
        self.id_cadastro = id_cadastro
        self.nome = nome
        self.email = email
        self.telefone = telefone
        self.senha = senha
        self.categoria = categoria
        self.ativo = ativo