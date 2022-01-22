"""
Scanner de portas em Python 3.x
Port Scanner
-
Diego Mendes Rodrigues
"""
import socket
import sys
from datetime import datetime

def scanner_no_ip(endereco_ip, exibir_portas_fechadas=0):
    # Realizar a varredura nas portas de um endereço IP
    print(f'Scanner no IP {endereco_ip}')

    # Portas que receberão uma tentativa de conexão
    portas = [20, 21, 22, 23, 42, 43, 43, 69, 80, 109, 110, 115, 118, 143,
              156, 220, 389, 443, 465, 513, 514, 530, 547, 587, 636, 873,
              989, 990, 992, 993, 995, 1433, 1521, 2049, 2081, 2083, 2086,
              3306, 3389, 5432, 5500, 5800]

    # Escaneando
    try:
        for porta in portas:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((endereco_ip, porta))
            if result == 0:
                print(f' {porta}')
            else:
                if exibir_portas_fechadas > 0:
                    print(f' {porta}')
            sock.close()
    except KeyboardInterrupt:
        print('Você pressionou <Ctrl>+<C>')
        sys.exit()

    except socket.gaierror:
        print('O hostname não pode ser resolvido')
        sys.exit()

    except socket.error:
        print('Não foi possível conectar no servidor')
        sys.exit()

# Execução do principal do script
if __name__ == '__main__':
    # IP local da máquina
    # ip_do_servidor = socket.gethostbyname(socket.gethostname())

    # Buscando o IP de uma URL
    ip_do_servidor = socket.gethostbyname('vivaolinux.com.br')

    # Data e hora inicial do escaneamento
    t1 = datetime.now()

    scanner_no_ip(ip_do_servidor)

    # Data e hora final do escaneamento
    t2 = datetime.now()
    total = t2 - t1
    print(f'Scanner finalizado em: {total}')