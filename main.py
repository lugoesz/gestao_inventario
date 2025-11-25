# Sistema de Gestão de Inventário com segurança (SHA-256 para login + Cifra de César para arquivo CSV)
# Arquivos: login.txt (hashes) e inventario.csv (dados cifrados, ; separador)

import hashlib

LOGIN_FILE = 'login.txt'
INVENTARIO_FILE = 'inventario.csv'
DELIM = ';'
CAESAR_SHIFT = 3  # ajuste simples para a cifra de César

# Utilitários: hashing e cifra
def sha256_hex(s): #Retorna o hash SHA-256 em hexdigest de uma string.
    return hashlib.sha256(s.encode()).hexdigest()

def caesar_encrypt_text(text, shift=CAESAR_SHIFT): #Cifra um texto com Cifra de César simples. Opera sobre caracteres imprimíveis. Preserva o separador (;) caso apareça — mas não devemos ter ; nos campos.
    res = []
    for ch in text:
        # cifrar apenas caracteres ASCII entre 32 e 126 para ficar simples
        code = ord(ch)
        if 32 <= code <= 126:
            base = 32
            width = 95  # 126 - 32 + 1
            new = ((code - base + shift) % width) + base
            res.append(chr(new))
        else:
            res.append(ch)
    return ''.join(res)

def caesar_decrypt_text(text, shift=CAESAR_SHIFT):
    return caesar_encrypt_text(text, -shift)

# Manipulação de arquivos
def ler_login(): #Lê login.txt. Retorna tuple (user_hash, pass_hash) ou (None, None) se vazio/ausente.
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

def carregar_inventario(): #Lê inventario.csv (cifrado), decifra campos e retorna dicionário:  { id_int: [nome_str, quantidade_int, preco_float, importado_bool] }
    inventario = {}
    try:
        with open(INVENTARIO_FILE, 'r') as f:
            for linha in f:
                linha = linha.strip()
                if not linha:
                    continue
                campos_cifrados = linha.split(DELIM)
                # decifrar cada campo
                campos = [caesar_decrypt_text(c) for c in campos_cifrados]
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

def salvar_inventario(inventario): #Recebe dicionário e grava inventario.csv (cifrando cada campo).
    with open(INVENTARIO_FILE, 'w') as f:
        for id_int, campos in inventario.items():
            nome, qtd, preco, importado = campos
            imp_str = 'True' if importado else 'False'
            linha = DELIM.join([str(id_int), nome, str(qtd), f'{preco:.2f}', imp_str])
            linha_cifrada = caesar_encrypt_text(linha)
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
    low = 0
    high = len(L) - 1
    chave = nome_busca.lower()
    while low <= high:
        mid = (low + high) // 2
        mid_name = L[mid][1].lower()
        if mid_name == chave:
            return mid, L[mid]
        elif mid_name < chave:
            low = mid + 1
        else:
            high = mid - 1
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
        nome_busca = input('Nome (busca por substring): ').strip()
        # busca linear
        resultados = busca_linear_por_nome(inventario, nome_busca)
        if resultados:
            print(f'Encontrados {len(resultados)} resultado(s):')
            for id_int, campos in resultados:
                nome, qtd, preco, imp = campos
                print(f'ID {id_int} -> {nome} | Qtd: {qtd} | Preço: R$ {preco:.2f} | Importado: {imp}')
        else:
            print('Nenhum produto encontrado.')
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

# Login / Autenticação
def criar_login_inicial():
    print('Arquivo de login vazio. Crie usuário e senha iniciais.')
    user = input('Novo usuário: ').strip()
    senha = input('Nova senha: ').strip()
    user_hash = sha256_hex(user)
    pass_hash = sha256_hex(senha)
    grava_login(user_hash, pass_hash)
    print('Usuário e senha gravados. Continue para login.')

def autenticar():
    user_hash_stored, pass_hash_stored = ler_login()
    if user_hash_stored is None:
        criar_login_inicial()
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



