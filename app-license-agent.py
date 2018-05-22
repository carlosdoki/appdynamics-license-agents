import json
import requests
import sys
import datetime
import base64

host = ''
port = ''
user = ''
password = ''
account = ''
linha = ''
cabecalho = ''
intervalo = ''
token = ''
cookies = ''

def get_auth(host, port, user, password, account):
    url = '{}:{}/controller/auth'.format(host, port)
    headers = {
        'Authorization': 'Basic ' + base64.b64encode(user + "@" + account + ":" + password)  
    }
    params = (
        ('action', 'login'),
    )
    response = requests.get(url, headers=headers, params=params)
    global token
    global cookies
    cookies = response.cookies 
    token = response.cookies.get("X-CSRF-TOKEN")

    return 0

def licencas():
    url = '{}:{}/controller/restui/licenseRule/getAllLicenseModuleProperties'.format(host, port)
    data = '''{
        "type": "BEFORE_NOW",
        "durationInMinutes": ''' + intervalo + ''',
        "endTime": null,
        "startTime": null,
        "timeRange": null,
        "timeRangeAdjusted": false }
        '''
    headers = {
        'Authorization': 'Basic ' + base64.b64encode(user + "@" + account + ":" + password),
        'X-CSRF-TOKEN' : token,
        'Content-Type': 'application/json',
        'Accept' : 'application/json, text/plain, */*'

    }
    r = requests.post(url, data=data, headers=headers, cookies=cookies)
    if r.status_code == 200:
        file = open('{}.csv'.format("licencas"),'w')
        texto='{};{}'.format("Tipo","Quantidade nos Ultimos " + intervalo + " mins")
        file.write(texto + '\n')
        data=r.json()
        data=json.dumps(data)
        data=json.loads(data)
        for tipo in data:
            data2=json.dumps(data[tipo])
            data2=json.loads(data2)
            if data2 is not None:
                texto='{};{}'.format(tipo, data2["peakUsage"])
                file.write(texto + '\n')
                #print(data2)
        file.close
    return 0
def agentes():
    url = '{}:{}/controller/restui/agent/setting/getAppServerAgents'.format(host, port)
    headers = {
        'Authorization': 'Basic ' + base64.b64encode(user + "@" + account + ":" + password),
        'X-CSRF-TOKEN' : token,
        'Content-Type': 'application/json',
        'Accept' : 'application/json, text/plain, */*'

    }
    params = {'output': 'json'}
    r = requests.get(url, params=params, headers=headers, cookies=cookies)
    if r.status_code == 200:
        file = open('{}.csv'.format("agents"),'w')
        texto='{};{};{};{}'.format("Aplicacao","NodeName","hostname","Tipo", "Versao")
        file.write(texto + '\n')
        for resposta in r.json():
            #print(resposta)
            #print()
            #print(resposta["hostName"])
            #print(resposta["applicationComponentNodeName"])
            #print(resposta["agentDetails"])
            agentDetails=json.dumps(resposta["agentDetails"])
            agentDetails=json.loads(agentDetails)
            #print(agentDetails["type"])
            #print(agentDetails["agentVersion"])
            texto='{};{};{};{};{}'.format(resposta["applicationName"],resposta["applicationComponentNodeName"], resposta["hostName"], agentDetails["type"],agentDetails["agentVersion"])
            file.write(texto + '\n')
        file.close    
    return 0

def process():
    get_auth(host, port, user, password, account)
    licencas()
    agentes()

    return 0

def main():
    global host
    global port
    global user
    global password
    global account
    global intervalo
    global cabecalho 

    if len(sys.argv) == 7 :
        host = sys.argv[1] 
        port = sys.argv[2]
        user = sys.argv[3]
        password = sys.argv[4]
        account = sys.argv[5]
        intervalo = sys.argv[6]

  
        cabecalho = '{};{}'.format(datetime.datetime.now(), intervalo)
        print(datetime.datetime.now())
        process()
        print(datetime.datetime.now())
    else:
        print 'app-license-agent.py <host> <port> <user> <password> <account> <intervalo>'
        sys.exit(2)

if __name__ == '__main__':
    main()
