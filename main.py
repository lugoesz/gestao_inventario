# Sistema de Gestão de Inventário com Segurança da Informação em Python
# Alunos:
# Giovanna Araujo Almeida - RA: 1680972511025
# Luiza Goes - RA:1680972511008
# Nelson S M Lisboa - RA:1680972511019
# Roan Silva dos Anjos- RA:1680972511018
# Gabriel 

# Arquivos: login.txt (hashes) e inventario.csv (dados cifrados, ; separador)

import hashlib
import os
from cryptography.fernet import Fernet

LOGIN_FILE = 'login.txt'
INVENTARIO_FILE = 'inventario.csv'
DELIM = ';'
FERNET_KEY_FILE = 'fernet.key'

# Utilitários: hashing e cifra
def sha256_hex(s): #Retorna o hash SHA-256 em hexdigest de uma string.
    return hashlib.sha256(s.encode()).hexdigest()

def ensure_fernet_key() -> bytes:
    """Gera uma chave Fernet e grava em FERNET_KEY_FILE se não existir, retorna a chave em bytes."""
    if os.path.exists(FERNET_KEY_FILE):
        with open(FERNET_KEY_FILE, 'rb') as kf:
            return kf.read()
    key = Fernet.generate_key()
    with open(FERNET_KEY_FILE, 'wb') as kf:
        kf.write(key)
    # arquivo gerado com a chave — guarde com cuidado
    return key

def get_fernet() -> Fernet:
    key = ensure_fernet_key()
    return Fernet(key)

def encrypt_field(field: str) -> str:
    """Encripta um campo (string) e retorna token (str)."""
    f = get_fernet()
    token = f.encrypt(field.encode('utf-8'))
    return token.decode('utf-8')

def decrypt_field(token_str: str) -> str:
    """Decifra token (str) e retorna o texto original."""
    f = get_fernet()
    try:
        plain = f.decrypt(token_str.encode('utf-8'))
        return plain.decode('utf-8')
    except Exception:
        # se não decifrar, retorna string vazia para forçar ignorar/validar posteriormente
        return ''

# Manipulação de arquivos
def ler_login(): #Lê login.txt. Retorna tupla (user_hash, pass_hash) ou (None, None) se vazio/ausente.
    try:
        with open(LOGIN_FILE, 'r') as f:
            linha = f.readline().strip()
            if not linha:
                return (None, None)
            parts = linha.split(DELIM)
            if len(parts) >= 2:
                return parts[0], parts[1]
            else:
                return (None, None)
    except FileNotFoundError:
        return (None, None)

def grava_login(user_hash, pass_hash):
    with open(LOGIN_FILE, 'w') as f:
        f.write(f'{user_hash}{DELIM}{pass_hash}\n')

def carregar_inventario(): #Lê inventario.csv (cifrado por campo), decifra campos e retorna dicionário
    inventario = {}
    try:
        with open(INVENTARIO_FILE, 'r') as f:
            for linha in f:
                linha = linha.strip()
                if not linha:
                    continue
                campos_cifrados = linha.split(DELIM)
                # decifrar cada campo usando Fernet
                campos = [decrypt_field(c) for c in campos_cifrados]
                # campo esperado: id;nome;quantidade;preco;importado
                try:
                    id_str, nome, qtd_str, preco_str, imp_str = campos
                    id_int = int(id_str)
                    qtd = int(qtd_str)
                    preco = float(preco_str)
                    importado = (imp_str.lower() in ('true','1','sim','s','yes'))
                    inventario[id_int] = [nome, qtd, preco, importado]
                except Exception:
                    # linha malformada - ignorar
                    continue
    except FileNotFoundError:
        # arquivo não existe => inventário vazio
        pass
    return inventario

def salvar_inventario(inventario): #Recebe dicionário e grava inventario.csv (cifrando cada campo com Fernet).
    with open(INVENTARIO_FILE, 'w') as f:
        for id_int, campos in inventario.items():
            nome, qtd, preco, importado = campos
            imp_str = 'True' if importado else 'False'
            # cifrar cada campo individualmente para manter separadores
            campos_texto = [str(id_int), nome, str(qtd), f'{preco:.2f}', imp_str]
            campos_cifrados = [encrypt_field(c) for c in campos_texto]
            linha_cifrada = DELIM.join(campos_cifrados)
            f.write(linha_cifrada + '\n')

# Validações
def validar_id(inventario, id_val):
    if id_val in inventario:
        return False
    return True

def validar_int(valor):
    try:
        return int(valor)
    except Exception:
        raise ValueError('Valor inteiro esperado.')

def validar_float(valor):
    try:
        return float(valor)
    except Exception:
        raise ValueError('Valor numérico esperado.')

def validar_bool(valor):
    v = valor.strip().lower()
    if v in ('sim','s','true','1','yes','y'):
        return True
    if v in ('nao','não','n','false','0','no'):
        return False
    raise ValueError('Valor booleano inválido (use sim/não).')

# Algoritmos de ordenação
def insertion_sort_list_by_name(L):
    # L é lista de tuplas (id, nome, qtd, preco, importado) ou [ [id, nome, ...], ... ]
    n = len(L)
    for k in range(1, n):
        x = L[k]
        i = k - 1
        while i >= 0 and L[i][1].lower() > x[1].lower():
            L[i+1] = L[i]
            i -= 1
        L[i+1] = x

def selection_sort_list_by_name(L):
    n = len(L)
    while n > 1:
        m = 0
        for i in range(1, n):
            if L[i][1].lower() > L[m][1].lower():
                m = i
        # m tem posição do maior pelo nome (comparamos > para achar maior e colocar no fim)
        L[m], L[n-1] = L[n-1], L[m]
        n -= 1

def merge_intercala(L, i, m, f):
    T = []
    x = i
    y = m+1
    while x <= m and y <= f:
        if L[x][1].lower() <= L[y][1].lower():
            T.append(L[x]); x += 1
        else:
            T.append(L[y]); y += 1
    while x <= m:
        T.append(L[x]); x += 1
    while y <= f:
        T.append(L[y]); y += 1
    for k in range(len(T)):
        L[i+k] = T[k]

def merge_sort_list_by_name(L, i, f):
    if i >= f: return
    m = (i + f)//2
    merge_sort_list_by_name(L, i, m)
    merge_sort_list_by_name(L, m+1, f)
    merge_intercala(L, i, m, f)

def ordenar_lista_por_nome(L): #Escolhe algoritmo automaticamente: insertion/selection para <=100, merge para >100. 
                               #L é lista de estruturas onde o campo [1] é o nome.
    n = len(L)
    if n <= 100:
        # uso insertion sort (poderia ser selection)
        insertion_sort_list_by_name(L)
    else:
        merge_sort_list_by_name(L, 0, n-1)

# Buscas
def busca_linear_por_nome(inventario, nome_busca): #Retorna lista de (id, [campos]) cujo nome contém nome_busca (case-insensitivo)
    resp = []
    chave = nome_busca.lower()
    for id_int, campos in inventario.items():
        nome = campos[0]
        if chave in nome.lower():
            resp.append((id_int, campos))
    return resp

def busca_id(inventario, id_busca):
    return inventario.get(id_busca)

def busca_binaria_por_nome_em_lista(L, nome_busca):
    #L deve estar ordenada por nome (cada item: (id, nome, qtd, preco, importado) ou [id,nome,...]).
    # Retorna (index, item) se encontrado (primeiro com nome exato), senão (-1, None).
    menor = 0
    maior = len(L) - 1
    chave = nome_busca.lower()
    while menor <= maior:
        meio = (menor + maior) // 2
        mid_name = L[meio][1].lower()
        if mid_name == chave:
            return meio, L[meio]
        elif mid_name < chave:
            menor = meio + 1
        else:
            maior = meio - 1
    return -1, None

# Operações sobre o dicionário
def adicionar_produto(inventario):
    try:
        id_str = input('ID (inteiro único): ').strip()
        id_int = validar_int(id_str)
        if not validar_id(inventario, id_int):
            print('ID já existe.')
            return
        nome = input('Nome: ').strip()
        qtd = validar_int(input('Quantidade (inteiro): ').strip())
        preco = validar_float(input('Preço (ex: 12.50): ').strip())
        imp = validar_bool(input('Importado? (sim/não): ').strip())
        inventario[id_int] = [nome, qtd, preco, imp]
        print('Produto adicionado na memória (será salvo ao encerrar).')
    except ValueError as e:
        print('Erro de entrada:', e)

def remover_produto(inventario):
    try:
        id_int = validar_int(input('ID do produto a remover: ').strip())
        if id_int in inventario:
            del inventario[id_int]
            print('Produto removido (na memória).')
        else:
            print('ID não encontrado.')
    except ValueError:
        print('ID inválido.')

def atualizar_produto(inventario):
    try:
        id_int = validar_int(input('ID do produto a atualizar: ').strip())
        if id_int not in inventario:
            print('ID não encontrado.')
            return
        nome, qtd, preco, imp = inventario[id_int]
        print('Deixe em branco para manter o valor atual.')
        novo_nome = input(f'Nome [{nome}]: ').strip()
        if novo_nome != '':
            nome = novo_nome
        entrada = input(f'Quantidade [{qtd}]: ').strip()
        if entrada != '':
            qtd = validar_int(entrada)
        entrada = input(f'Preço [{preco:.2f}]: ').strip()
        if entrada != '':
            preco = validar_float(entrada)
        entrada = input(f'Importado? (sim/não) [{ "sim" if imp else "não" }]: ').strip()
        if entrada != '':
            imp = validar_bool(entrada)
        inventario[id_int] = [nome, qtd, preco, imp]
        print('Produto atualizado (na memória).')
    except ValueError as e:
        print('Erro de entrada:', e)

def exibir_todos_produtos(inventario):
    # Transformar dicionário em lista para ordenar por nome
    L = []
    for id_int, campos in inventario.items():
        L.append([id_int, campos[0], campos[1], campos[2], campos[3]])
    if not L:
        print('Inventário vazio.')
        return
    ordenar_lista_por_nome(L)
    # Mostrar tabela simples
    # descobrir largura do nome
    maior = max(len(item[1]) for item in L)
    cab = f'{"ID":^6} | {"NOME":^{maior}} | {"QTD":^6} | {"PREÇO":^10} | {"IMP"}'
    print('-' * len(cab))
    print(cab)
    print('-' * len(cab))
    for it in L:
        id_int, nome, qtd, preco, imp = it
        print(f'{id_int:^6} | {nome:{maior}} | {qtd:^6} | R$ {preco:8.2f} | {"SIM" if imp else "NAO"}')
    print('-' * len(cab))

def buscar_produto(inventario):
    modo = input('Buscar por (1) ID ou (2) Nome? ').strip()
    if modo == '1':
        try:
            id_int = validar_int(input('ID: ').strip())
            item = busca_id(inventario, id_int)
            if item:
                nome, qtd, preco, imp = item
                print(f'ID {id_int} -> {nome} | Qtd: {qtd} | Preço: R$ {preco:.2f} | Importado: {imp}')
            else:
                print('ID não encontrado.')
        except ValueError:
            print('ID inválido.')
    elif modo == '2':
        sub = input('Buscar por (1) substring (linear) ou (2) nome exato (binária)? ').strip()
        if sub == '1':
            nome_busca = input('Nome (busca por substring): ').strip()
            resultados = busca_linear_por_nome(inventario, nome_busca)
            if resultados:
                print(f'Encontrados {len(resultados)} resultado(s):')
                for id_int, campos in resultados:
                    nome, qtd, preco, imp = campos
                    print(f'ID {id_int} -> {nome} | Qtd: {qtd} | Preço: R$ {preco:.2f} | Importado: {imp}')
            else:
                print('Nenhum produto encontrado.')
        elif sub == '2':
            nome_exato = input('Nome (exato): ').strip()
            # preparar lista ordenada e usar busca binária
            L = []
            for id_int, campos in inventario.items():
                L.append([id_int, campos[0], campos[1], campos[2], campos[3]])
            if not L:
                print('Inventário vazio.')
                return
            ordenar_lista_por_nome(L)
            idx, item = busca_binaria_por_nome_em_lista(L, nome_exato)
            if idx != -1:
                id_int, nome, qtd, preco, imp = item
                print(f'Encontrado: ID {id_int} -> {nome} | Qtd: {qtd} | Preço: R$ {preco:.2f} | Importado: {imp}')
            else:
                print('Produto não encontrado (busca binária).')
        else:
            print('Opção inválida.')
    else:
        print('Opção inválida.')

def estatisticas(inventario):
    num = len(inventario)
    valor_total = 0.0
    total_importados = 0
    for id_int, campos in inventario.items():
        nome, qtd, preco, imp = campos
        valor_total += qtd * preco
        if imp:
            total_importados += 1
    print('--- Estatísticas ---')
    print(f'Total de produtos cadastrados: {num}')
    print(f'Valor total do estoque: R$ {valor_total:.2f}')
    print(f'Quantidade de produtos importados: {total_importados}')

# Login / Autenticação -> haverá apenas um login neste arquivo 
def criar_login(): 
    print('Arquivo de login vazio. Crie usuário e senha iniciais.')  # a primeira vez que o programa for executado esse arquivo estará vazio e será solicitado um usuário e senha iniciais
    user = input('Novo usuário: ').strip()
    senha = input('Nova senha: ').strip()
    user_hash = sha256_hex(user)
    pass_hash = sha256_hex(senha)
    grava_login(user_hash, pass_hash)
    print('Usuário e senha gravados. Continue para login.')

def autenticar():
    user_hash_stored, pass_hash_stored = ler_login()
    if user_hash_stored is None:
        criar_login()
        user_hash_stored, pass_hash_stored = ler_login()
    # tentar autenticar
    while True:
        user = input('Usuário: ').strip()
        senha = input('Senha: ').strip()
        if sha256_hex(user) == user_hash_stored and sha256_hex(senha) == pass_hash_stored:
            print('Autenticado com sucesso!')
            return True
        else:
            print('Usuário ou senha incorretos. Tente novamente.')

def editar_login():
    print('Alterar usuário e senha:')
    user = input('Novo usuário: ').strip()
    senha = input('Nova senha: ').strip()
    grava_login(sha256_hex(user), sha256_hex(senha))
    print('Login atualizado!')

# menu principal
def menu_principal():
    inventario = carregar_inventario()
    print(f'Inventário carregado. {len(inventario)} produto(s) na memória.')
    while True:
        print('\n--- MENU ---')
        print('1 - Adicionar produto')
        print('2 - Remover produto')
        print('3 - Atualizar produto')
        print('4 - Exibir todos os produtos')
        print('5 - Buscar produto (por ID ou nome)')
        print('6 - Estatísticas do inventário')
        print('7 - Editar usuário/senha')
        print('0 - Salvar e encerrar')
        op = input('Escolha como prosseguir: ').strip()
        if op == '1':
            adicionar_produto(inventario)
        elif op == '2':
            remover_produto(inventario)
        elif op == '3':
            atualizar_produto(inventario)
        elif op == '4':
            exibir_todos_produtos(inventario)
        elif op == '5':
            buscar_produto(inventario)
        elif op == '6':
            estatisticas(inventario)
        elif op == '7':
            editar_login()
        elif op == '0':
            # salvar e sair
            salvar_inventario(inventario)
            print('Inventário salvo! Saindo...')
            break
        else:
            print('Opção inválida.')

def main():
    print('--- Sistema de Gestão de Inventário ---')
    autenticar()
    menu_principal()

main()





