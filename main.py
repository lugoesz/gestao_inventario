# Sistema de Gestão de Inventário com Segurança da Informação em Python
# Alunos:
# Giovanna Araujo Almeida - RA: 1680972511025
# Luiza Goes - RA:1680972511008
# Nelson S M Lisboa - RA:1680972511019
# Roan Silva dos Anjos- RA:1680972511018
# Gabriel 

# Arquivos: login.txt (hashes) e inventario.csv (dados cifrados, ; separador)

import hashlib # usado para gerar hashes SHA-256 para login
import os # disponível para operações com o sistema de arquivos

LOGIN_FILE = 'login.txt'                 # arquivo que guarda usuário e senha (hash)
INVENTARIO_FILE = 'inventario.csv'       # arquivo que guarda inventário (campos cifrados)
DELIM = ';'                              # DELIM = DELIMITADOR -> separador CSV utilizado no arquivo
CAESAR_SHIFT = 5                         # deslocamento da Cifra de César (chave usada para cifrar/decifrar)

# ---------------- HASHING E CIFRA -------------------------
def sha256_hex(s): #Retorna o hash SHA-256 em hexdigest de uma string. -> hexdigest = hash em forma de texto
    return hashlib.sha256(s.encode()).hexdigest()

# Cifra um campo (string) usando Cifra de César aplicando shift somente em letras.
def encrypt_field(field: str) -> str:
    #Encripta um campo (string) com Cifra de César e retorna token (str) -> resultado é uma lista de caracteres que será juntada no final
    resultado = []
    # percorre cada caractere do campo
    for char in field:
        # se for letra (maiúscula ou minúscula) aplica deslocamento circular
        if char.isalpha():
            # diferencia maiúscula de minúscula para manter case
            if char.isupper():
                # Cifra maiúsculas
                novo_char = chr((ord(char) - ord('A') + CAESAR_SHIFT) % 26 + ord('A'))
            else:
                # Cifra minúsculas -> letra vira um número, soma 5, se passar de Z recomeça em A, e depois volta a virar letra
                novo_char = chr((ord(char) - ord('a') + CAESAR_SHIFT) % 26 + ord('a'))
            resultado.append(novo_char)
        else:
            # se não for letra (número, espaço, pontuação), mantém sem alteração
            resultado.append(char)
    # junta lista de caracteres e retorna string cifrada
    return ''.join(resultado)

# Decifra um token gerado por encrypt_field
def decrypt_field(token_str: str) -> str:
    # decifra token (str) com Cifra de César inversa e retorna o texto original
    try:
        resultado = []
        for char in token_str:
            if char.isalpha():
                # aplica deslocamento inverso, mantendo maiúsculas/minúsculas
                if char.isupper():
                    # Decifra maiúsculas
                    novo_char = chr((ord(char) - ord('A') - CAESAR_SHIFT) % 26 + ord('A'))
                else:
                    # Decifra minúsculas
                    novo_char = chr((ord(char) - ord('a') - CAESAR_SHIFT) % 26 + ord('a'))
                resultado.append(novo_char)
            else:
                # Mantém números, espaços e caracteres especiais
                resultado.append(char)
        return ''.join(resultado)
    except Exception:
        # se não decifrar, retorna string vazia para forçar ignorar/validar posteriormente
        return ''

# --------------------------- MANIPULAÇÃO DE ARQUIVOS ----------------------------------
def ler_login(): #Lê login.txt. Retorna tupla (user_hash, pass_hash) ou (None, None) se vazio/ausente.
    try:
        with open(LOGIN_FILE, 'r') as f:
            linha = f.readline().strip()
            if not linha:
                # arquivo vazio ou primeira linha vazia
                return (None, None)
            parts = linha.split(DELIM) # separa por ';'
            if len(parts) >= 2:
                # retorna tupla (user_hash, pass_hash)
                return parts[0], parts[1]
            else:
                # formato inesperado -> trata como sem login
                return (None, None)
    except FileNotFoundError:
        # arquivo não existe ainda -> primeiro uso
        return (None, None)
        
# Grava user_hash e pass_hash em login.txt (sobrescreve)
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
                    # pula linhas vazias
                    continue
                # separa os campos cifrados pelo delimitador
                campos_cifrados = linha.split(DELIM)
                # decifra cada campo (retorna lista de strings)
                campos = [decrypt_field(c) for c in campos_cifrados]
                # campo esperado: id;nome;quantidade;preco;importado
                try:
                    id_str, nome, qtd_str, preco_str, imp_str = campos
                    # converte para tipos corretos
                    id_int = int(id_str)
                    qtd = int(qtd_str)
                    preco = float(preco_str)
                    importado = (imp_str.lower() in ('true','1','sim','s','yes'))
                     # armazena no dicionário com chave inteira
                    inventario[id_int] = [nome, qtd, preco, importado]
                except Exception:
                    # linha malformada - ignorar
                    continue
    except FileNotFoundError:
        # arquivo não existe => inventário vazio
        pass
    return inventario
    
# Salva o inventário cifrando campo a campo e escrevendo no CSV
def salvar_inventario(inventario):
    with open(INVENTARIO_FILE, 'w') as f:
        for id_int, campos in inventario.items():
            nome, qtd, preco, importado = campos
            # converte booleano para string padronizada
            imp_str = 'True' if importado else 'False'
            # cifrar cada campo individualmente para manter separadores
            campos_texto = [str(id_int), nome, str(qtd), f'{preco:.2f}', imp_str]
            # cifra cada campo individualmente para manter separadores claros
            campos_cifrados = [encrypt_field(c) for c in campos_texto]
            linha_cifrada = DELIM.join(campos_cifrados) 
             # escreve a linha cifrada no arquivo
            f.write(linha_cifrada + '\n')

# ------------------- VALIDAÇÕES ----------------------
# verifica se ID é único no inventário (True = válido)
def validar_id(inventario, id_val):
    if id_val in inventario:
        return False
    return True

# converte string para inteiro, lançando ValueError se falhar
def validar_int(valor):
    try:
        return int(valor)
    except Exception:
        raise ValueError('Valor inteiro esperado.')

# converte string para float, lançando ValueError se falhar
def validar_float(valor):
    try:
        return float(valor)
    except Exception:
        raise ValueError('Valor numérico esperado.')
        
# converte respostas de usuário para booleano (sim/não etc.)
def validar_bool(valor):
    v = valor.strip().lower()
    if v in ('sim','s','true','1','yes','y'):
        return True
    if v in ('nao','não','n','false','0','no'):
        return False
    raise ValueError('Valor booleano inválido (use sim/não).')

# ------------------ ORDENAÇÃO ---------------------
#INSERTION SORT POR NOME 
def is_nome(L):
    # L é lista de tuplas (id, nome, qtd, preco, importado) ou [ [id, nome, ...], ... ]
    n = len(L)
    for k in range(1, n):
        x = L[k]
        i = k - 1
        # move elementos maiores para a direita até achar posição correta
        while i >= 0 and L[i][1].lower() > x[1].lower():
            L[i+1] = L[i]
            i -= 1
        L[i+1] = x

# SELECTION SORT POR NOME 
def ss_nome(L):
    n = len(L)
    while n > 1:
        m = 0
        for i in range(1, n):
            if L[i][1].lower() > L[m][1].lower():
                m = i
        # m tem posição do maior pelo nome (comparamos > para achar maior e colocar no fim)
        L[m], L[n-1] = L[n-1], L[m]
        n -= 1

# Função auxiliar do merge sort: intercala duas metades já ordenadas
def merge_intercala(L, i, m, f):
    T = []
    x = i
    y = m+1
    # percorre as duas metades e vai juntando em ordem
    while x <= m and y <= f:
        if L[x][1].lower() <= L[y][1].lower():
            T.append(L[x]); x += 1
        else:
            T.append(L[y]); y += 1
    # copia o restante das metades
    while x <= m:
        T.append(L[x]); x += 1
    while y <= f:
        T.append(L[y]); y += 1
     # copia de volta para L na posição correta
    for k in range(len(T)):
        L[i+k] = T[k]

# Merge sort recursivo para ordenar por nome
def ms_nome(L, i, f):
    if i >= f: return
    m = (i + f)//2
    ms_nome(L, i, m)
    ms_nome(L, m+1, f)
    merge_intercala(L, i, m, f)

def ordenar_lista_nome(L): #Escolhe algoritmo automaticamente: insertion/selection para <=100, merge para >100. 
                               #L é lista de estruturas onde o campo [1] é o nome.
    n = len(L)
    if n <= 100:
        # uso insertion sort (poderia ser selection)
        is_nome(L)
    else:
        ms_nome(L, 0, n-1)

#--------------- BUSCAS --------------------
# Busca linear por substring no nome
# Retorna lista de tuplas (id, campos) encontradas
def bl_nome(inventario, nome_busca):
    resp = []
    chave = nome_busca.lower()
    for id_int, campos in inventario.items():
        nome = campos[0]
        if chave in nome.lower():
            resp.append((id_int, campos))
    return resp

#Busca por ID (acesso direto no dicionário)
def busca_id(inventario, id_busca):
    return inventario.get(id_busca)
    
# Busca binária para lista de registros [id, nome, qtd, preco, importado]
# L deve estar ordenada por nome antes de chamar esta função
# Retorna (index, item) se encontrado, senão (-1, None)
def bb_nome(L, nome_busca):
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

# ---------------- OPERAÇÕES NO DICIONÁRIO ---------------------------------
# adiciona um produto ao dicionário em memória (valida entradas)
def adicionar_produto(inventario):
    try:
        # lê ID como string e valida/ converte para int
        id_str = input('ID (inteiro único): ').strip()
        id_int = validar_int(id_str)
        # verifica se ID ainda NÃO existe no inventário
        if not validar_id(inventario, id_int):
            print('ID já existe.')
            return
        nome = input('Nome: ').strip()
        qtd = validar_int(input('Quantidade (inteiro): ').strip())
        preco = validar_float(input('Preço (ex: 12.50): ').strip())
        imp = validar_bool(input('Importado? (sim/não): ').strip())
        # salva no dicionário (em memória)
        inventario[id_int] = [nome, qtd, preco, imp]
        print('Produto adicionado na memória (será salvo ao encerrar).')
    except ValueError as e:
        print('Erro de entrada:', e)

# Remove produto pelo ID (apenas da memória)
def remover_produto(inventario):
    try:
        id_int = validar_int(input('ID do produto a remover: ').strip())
        if id_int in inventario:
            del inventario[id_int]
            print('Produto removido da memória.')
        else:
            print('ID não encontrado.')
    except ValueError:
        print('ID inválido.')

# Atualiza campos de um produto (permite manter valores em branco)
def atualizar_produto(inventario):
    try:
        id_int = validar_int(input('ID do produto a atualizar: ').strip())
        if id_int not in inventario:
            print('ID não encontrado.')
            return
         # obtém valores atuais
        nome, qtd, preco, imp = inventario[id_int]
        print('Deixe em branco para manter o valor atual.')
        # para cada campo, se usuário digitar algo, atualiza; senão mantém
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
        # salva atualização
        inventario[id_int] = [nome, qtd, preco, imp]
        print('Produto atualizado na memória!')
    except ValueError as e:
        print('Erro de entrada:', e)

# exibe todos produtos em tabela compacta, ordenados por nome
def exibir_produtos(inventario):
    # transforma dicionário em lista para ordenação por nome
    L = []
    for id_int, campos in inventario.items():
        L.append([id_int, campos[0], campos[1], campos[2], campos[3]])
    if not L:
        print('Inventário vazio.')
        return
    # ordena por nome usando função que escolhe algoritmo automaticamente (merge ou insertion sort)
    ordenar_lista_nome(L)
    # calcula largura da coluna nome para alinhamento
    maior = max(len(item[1]) for item in L)
    # cabeçalho formatado -> cab = cabeçalho
    cab = f'{"ID":^6} | {"NOME":^{maior}} | {"QTD":^6} | {"PREÇO":^10} | {"IMP"}'
    print('-' * len(cab))
    print(cab)
    print('-' * len(cab))
    # formatação
    for it in L:
        id_int, nome, qtd, preco, imp = it
        print(f'{id_int:^6} | {nome:{maior}} | {qtd:^6} | R$ {preco:8.2f} | {"SIM" if imp else "NAO"}')
    print('-' * len(cab))

#busca: tenta interpretar entrada como ID (int); se falhar, trata como nome
def buscar_produto(inventario):
    termo = input("Digite o ID ou o nome do produto: ").strip()

    if not inventario:
        print("Inventário vazio.")
        return
        
    # tenta interpretar como ID
    try:
        id_val = int(termo)   # se converter, busca por ID 
        item = busca_id(inventario, id_val)

        if item:
            nome, qtd, preco, imp = item
            print("(Busca por ID)")
            print(f"ID {id_val} | {nome} | Qtd: {qtd} | Preço: R$ {preco:.2f} | Importado: {imp}")
        else:
            print("ID não encontrado.")
        return 

    except:
        # se cair aqui, NÃO é ID → trata como nome e vai para a BUSCA POR NOME
        pass

    # BUSCA POR NOME
    # monta lista temporária no formato do sistema para ordenar/consultar
    L = []
    for id_int, campos in inventario.items():
        L.append([id_int, campos[0], campos[1], campos[2], campos[3]])

    # ordenar por nome (necessário para busca binária)
    ordenar_lista_nome(L)

    # 1 - tenta busca binária (nome exato)
    idx, item = bb_nome(L, termo)
    if idx != -1:
        id_int, nome, qtd, preco, imp = item
        print("(Busca binária — nome exato)")
        print(f"ID {id_int} | {nome} | Qtd: {qtd} | Preço: R$ {preco:.2f} | Importado: {imp}")
        return

    # 2 - se não achar nome exato → busca linear (substring) -> SUBSTRING = se o termo digitado pelo usuário estiver contido dentro do nome, mesmo que não seja o nome completo, então é uma substring
    print("(Busca linear — substring)")
    encontrou = False

    for item in L:
        id_int, nome, qtd, preco, imp = item
        if termo.lower() in nome.lower():
            encontrou = True
            print(f"ID {id_int} | {nome} | Qtd: {qtd} | Preço: R$ {preco:.2f} | Importado: {imp}")

    if not encontrou:
        print("Nenhum produto encontrado.")

# -------------- ESTATÍSTICAS --------------------
# calcula número total de itens, valor total do estoque e quantidade de importados
def estatisticas(inventario):
    num = len(inventario)
    valor_total = 0.0
    total_importados = 0
    # percorre o dicionário somando qtd * preco
    for id_int, campos in inventario.items():
        nome, qtd, preco, imp = campos
        valor_total += qtd * preco
        if imp:
            total_importados += 1
    print('--- Estatísticas ---')
    print(f'Total de produtos cadastrados: {num}')
    print(f'Valor total do estoque: R$ {valor_total:.2f}')
    print(f'Quantidade de produtos importados: {total_importados}')

# ------------------ LOGIN / AUTENTICAÇÃO ---------------------
# cria login inicial caso login.txt esteja vazio (primeira execução) -> apenas um por arquivo
def criar_login(): 
    print('Arquivo de login vazio. Crie usuário e senha iniciais.')  # a primeira vez que o programa for executado esse arquivo estará vazio e será solicitado um usuário e senha iniciais
    user = input('Novo usuário: ').strip()
    senha = input('Nova senha: ').strip()
    user_hash = sha256_hex(user)
    pass_hash = sha256_hex(senha)
    grava_login(user_hash, pass_hash)
    print('Usuário e senha gravados. Continue para login.')

# loop de autenticação que verifica hashes
def autenticar():
    user_hash_stored, pass_hash_stored = ler_login()
    if user_hash_stored is None:
        criar_login()
        user_hash_stored, pass_hash_stored = ler_login()
    # tentar autenticar
    while True:
        user = input('Usuário: ').strip()
        senha = input('Senha: ').strip()
        # compara hashes gerados com os hashes armazenados        
        if sha256_hex(user) == user_hash_stored and sha256_hex(senha) == pass_hash_stored:
            print('Autenticado com sucesso!')
            return True
        else:
            print('Usuário ou senha incorretos. Tente novamente.')

# permite alterar usuário e senha (sobrescreve login.txt)
def editar_login():
    print('Alterar usuário e senha:')
    user = input('Novo usuário: ').strip()
    senha = input('Nova senha: ').strip()
    grava_login(sha256_hex(user), sha256_hex(senha))
    print('Login atualizado!')

# ------------------ MENU PRINCIPAL E MAIN -----------------------
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
            exibir_produtos(inventario)
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


