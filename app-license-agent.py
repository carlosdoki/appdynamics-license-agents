import json
import requests
import sys
import datetime
import base64
import re

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
    data_string = user + "@" + account + ":" + password
    data_bytes = data_string.encode("utf-8")
    headerBasic = base64.b64encode(data_bytes).decode('utf-8')
    print(headerBasic)
    headers = {
        'Authorization': 'Basic ' + headerBasic
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
def applications():
    url = '{}:{}/controller/restui/v1/app/list/all'.format(
        host, port)
    data = '''{"requestFilter":{"filters":[{"field":"TYPE","criteria":"APM","operator":"EQUAL_TO"}],"queryParams":null},"searchFilters":[],"timeRangeStart":1672225001867,"timeRangeEnd":1672228601867,"columnSorts":[{"column":"CALLS","direction":"DESC"}],"resultColumns":["NAME"],"offset":0,"limit":-1}'''
    data_string = user + "@" + account + ":" + password
    data_bytes = data_string.encode("utf-8")
    headerBasic = base64.b64encode(data_bytes).decode('utf-8')
    headers = {
        'Authorization': 'Basic ' + headerBasic,
        'X-CSRF-TOKEN': token,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/plain, */*'

    }
    r = requests.post(url, data=data, headers=headers, cookies=cookies)
    if r.status_code == 200:
        file = open('{}.csv'.format("agents"), 'w')
        texto = '{};{};{};{};{};{};{}'.format(
            "Aplicacao", "NodeName", "machineName", "SO", "Versao", "IP", "TierName")  
        file.write(texto + '\n')
        data = r.json()
        total = json.dumps(data['totalCount'])
        total = json.loads(total)
        data = json.dumps(data['data'])
        data = json.loads(data)
        _total = 1
        for resposta in data:
            print("{}/{}".format(_total, total))
            node(resposta, file)
            _total = _total + 1
        file.close
    return 0

def node(application, file):
    url = '{}:{}/controller/restui/v1/nodes/list/health'.format(
        host, port)
    data = '{"requestFilter":{"queryParams":{"applicationId":' + str(application) + ',"performanceDataFilter":"REPORTING"},"filters":[]},"resultColumns":["NODE_NAME","TIER"],"offset":0,"limit":-1,"searchFilters":[],"columnSorts":[{"column":"TIER","direction":"ASC"}],"timeRangeStart":1672229921520,"timeRangeEnd":1672233521520}'
    data_string = user + "@" + account + ":" + password
    data_bytes = data_string.encode("utf-8")
    headerBasic = base64.b64encode(data_bytes).decode('utf-8')
    headers = {
        'Authorization': 'Basic ' + headerBasic,
        'X-CSRF-TOKEN': token,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/plain, */*'

    }
    r = requests.post(url, data=data, headers=headers, cookies=cookies)
    if r.status_code == 200:
        data = r.json()
        data = json.dumps(data['data'])
        data = json.loads(data)
        for resposta in data:
            nodeId = resposta['nodeId']
            tierName = resposta['componentName']
            nodeDetails(application, nodeId, tierName, file)
    return 0

def nodeDetails(application, nodeId, tierName, file):
    url = '{}:{}/controller/restui/components/getNodeViewData/{}/{}'.format(
        host, port, application, nodeId)
    data_string = user + "@" + account + ":" + password
    data_bytes = data_string.encode("utf-8")
    headerBasic = base64.b64encode(data_bytes).decode('utf-8')
    headers = {
        'Authorization': 'Basic ' + headerBasic,
        'X-CSRF-TOKEN': token,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/plain, */*'

    }
    r = requests.get(url, headers=headers, cookies=cookies)
    if r.status_code == 200:
        data = r.json()
        dataApp = json.dumps(data['application'])
        dataApp = json.loads(dataApp)
        appName = dataApp['name']
        data = json.dumps(data['applicationComponentNode'])
        data = json.loads(data)
        nodeName = data['name']
        machineName = data['machineName']
        nodeOS = data['machineOSType']['name']
        nodeIP = ""
        try:
            nodeAppVersion = data['appAgent']['agentVersion']
        except:
            nodeAppVersion = ""
        for meta in data['metaInfo']:
            if (meta['name'] == 'appdynamics.ip.addresses'):
                anodeIP = re.findall(r',\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', meta['value'])
                nodeIP = ' '.join(anodeIP)
        nodeAvaliable(appName, nodeName, machineName, nodeOS, nodeAppVersion, nodeIP, tierName, nodeId, file)
    return 0

def nodeAvaliable(appName, nodeName, machineName, nodeOS, nodeAppVersion, nodeIP, tierName, nodeId, file):
    url = '{}:{}/controller/restui/nodeUiService/getAgentAvailabilitySummaryForNode/{}?timerange=Custom_Time_Range.BETWEEN_TIMES.1672241078366.1672237478366.60'.format(
        host, port, nodeId)
    data_string = user + "@" + account + ":" + password
    data_bytes = data_string.encode("utf-8")
    headerBasic = base64.b64encode(data_bytes).decode('utf-8')
    headers = {
        'Authorization': 'Basic ' + headerBasic,
        'X-CSRF-TOKEN': token,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/plain, */*'

    }
    r = requests.get(url, headers=headers, cookies=cookies)
    if r.status_code == 200:
        data = r.json()
        percentage = json.dumps(data['percentage'])
        percentage = json.loads(percentage)
        texto = '{};{};{};{};{};{};{}'.format(appName, nodeName, machineName, nodeOS, nodeAppVersion, nodeIP, tierName)
        # print("percentage={} - {}".format(percentage, texto))
        if (percentage > 0):
            file.write(texto + '\n')
    return 0

def licencas():
    url = '{}:{}/controller/restui/licenseRule/getAllLicenseModuleProperties'.format(
        host, port)
    data = '''{
        "type": "BEFORE_NOW",
        "durationInMinutes": ''' + intervalo + ''',
        "endTime": null,
        "startTime": null,
        "timeRange": null,
        "timeRangeAdjusted": false }
        '''
    data_string = user + "@" + account + ":" + password
    data_bytes = data_string.encode("utf-8")
    headerBasic = base64.b64encode(data_bytes).decode('utf-8')
    headers = {
        'Authorization': 'Basic ' + headerBasic,
        'X-CSRF-TOKEN': token,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/plain, */*'

    }
    r = requests.post(url, data=data, headers=headers, cookies=cookies)
    if r.status_code == 200:
        file = open('{}.csv'.format("licencas"), 'w')
        texto = '{};{}'.format(
            "Tipo", "Quantidade nos Ultimos " + intervalo + " mins")
        file.write(texto + '\n')
        data = r.json()
        data = json.dumps(data)
        data = json.loads(data)
        for tipo in data:
            data2 = json.dumps(data[tipo])
            data2 = json.loads(data2)
            if data2 is not None:
                texto = '{};{}'.format(tipo, data2["peakUsage"])
                file.write(texto + '\n')
                # print(data2)
        file.close
    return 0


def agentes():
    url = '{}:{}/controller/restui/agent/setting/getAppServerAgents'.format(
        host, port)
    data_string = user + "@" + account + ":" + password
    data_bytes = data_string.encode("utf-8")
    headerBasic = base64.b64encode(data_bytes).decode('utf-8')
    headers = {
        'Authorization': 'Basic ' + headerBasic,
        'X-CSRF-TOKEN': token,
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/plain, */*'

    }
    params = {'output': 'json'}
    r = requests.get(url, params=params, headers=headers, cookies=cookies)
    if r.status_code == 200:
        file = open('{}.csv'.format("agents"), 'w')
        texto = '{};{};{};{}'.format(
            "Aplicacao", "NodeName", "hostname", "Tipo", "Versao")
        file.write(texto + '\n')
        for resposta in r.json():
            # print(resposta)
            # print()
            # print(resposta["hostName"])
            # print(resposta["applicationComponentNodeName"])
            # print(resposta["agentDetails"])
            agentDetails = json.dumps(resposta["agentDetails"])
            agentDetails = json.loads(agentDetails)
            # print(agentDetails["type"])
            # print(agentDetails["agentVersion"])
            texto = '{};{};{};{};{}'.format(resposta["applicationName"], resposta["applicationComponentNodeName"],
                                            resposta["hostName"], agentDetails["type"], agentDetails["agentVersion"])
            file.write(texto + '\n')
        file.close
    return 0


def process():
    get_auth(host, port, user, password, account)
    # licencas()
    # agentes()
    applications()

    return 0


def main():
    global host
    global port
    global user
    global password
    global account
    global intervalo
    global cabecalho

    if len(sys.argv) == 7:
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
        print('app-license-agent.py <host> <port> <user> <password> <account> <intervalo>')
        sys.exit(2)


if __name__ == '__main__':
    main()
