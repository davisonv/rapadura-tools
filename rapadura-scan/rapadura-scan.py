# Um portscan simples consumindo a api do Shodan
import socket
import shodan

#tratar o alvo
host = input("Digite a url do alvo:")
ip = socket.gethostbyname(host)

SHODAN_API_KEY = "VEwqH1TXvRWKxeQ1eAmNoE1zvNLb3iMo"

api = shodan.Shodan(SHODAN_API_KEY)

# analisa o host
host = api.host(ip)

# imprime as informações gerais
print("""
        IP: {}
        Organization: {}
        Operating System: {}
""".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))

#imprime os banners
for item in host['data']:
        print("""
                Port: {}
                Banner: {}
        """.format(item['port'], item['data']))
