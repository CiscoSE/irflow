'''
irflow - Incident Response Workflow

This app enables security operations or an incident responder to leverage the Cisco security applications and tools to quickly assess hosts that have been compromised and respond by isolating them from the network.  In addition, the responder can identify malicious sources of information and use Umbrella and Firepower to block them, preventing other hosts from potential compromise from known malicious sources.

Script Dependencies:
    requests
    datetime
    tinydb
    flask
    ciscosparkapi
    pyyaml
    time
    random
    sys
    xml.etree

Depencency Installation:
    $ pip install -r requirements.txt

Copyright (c) 2019, Cisco Systems, Inc. All rights reserved.
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

# import requests library
import requests
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

import datetime #import datetime for ISO 8601 timestamps
from tinydb import TinyDB,Query #import database for storing results locally.
from flask import Flask  #import web application
import ciscosparkapi #Webex Teams features for creating rooms
import yaml #YAML for working with the config.yml
import time
import sys
from xml.etree import ElementTree

#Initialize Flask and import routes from routes.py
app = Flask(__name__)
wsgi_app = app.wsgi_app
from routes import *

#Open the config.yml file to retreive configuration details
with open("config.yml", 'r') as stream:
    try:
        config = yaml.load(stream)
    except yaml.YAMLError as exc:
        print(exc)

#Initialize databases for storing data locally
hosts_db = TinyDB('hosts_db.json')
threats_db = TinyDB('threats_db.json')
domains_db = TinyDB('domains_db.json')
querydb = Query()

def testing():
    print ('Starting...')

    'These commands were used while testing the app from command line and can be safely ignored'

    #get_investigate_security_scores("bing.com")
    #get_investigate_domains("[\"www.bing.com\",\"github.com\",\"www.bing.com\",\"codeload.github.com\",\"7tno4hib47vlep5o.tor2web.fi\"]")
    #get_samples_from_threatgrid("ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
    #find_malware_events_from_cognitive()
    #find_malware_events_from_amp()
    #incident_room = create_new_webex_teams_incident_room()
    #block_with_umbrella('gibberish.com')
    list_blocked_domains_from_umbrella()


def find_malware_events_from_amp():
    '''
    Identifies indications of compromise from AMP for Endpoints.  Itemizes all hosts where AMP identifies malware was successfully executed
    '''

    url = "https://%(client)s:%(key)s@api.amp.cisco.com/v1/events" % {'client':config['amp4e']['client_id'], 'key':config['amp4e']['api_key']}

    querystring = {"event_type[]":"1107296272"}

    headers = {
    'Cache-Control': "no-cache",
    }

    response = requests.request("GET", url, headers=headers, params=querystring)

    #Create a list of the SHA256s
    sha256s = []

    for item in response.json()['data']:

        #Add unique SHA256s to a list to send to Threatgrid
        if item['file']['identity']['sha256'] not in sha256s:
            sha256s.append(item['file']['identity']['sha256'])

        #Check to see if the host is in the database or not.  If not add it.
        if bool(hosts_db.get(querydb.hostname == item['computer']['hostname'])) == False:

            logged_in = find_active_user_from_ise((item['computer']['network_addresses'])[0]['ip'])
            building = 'building'
            floor = 'floor'
            responder = 'responder'

            hosts_db.insert({'date':item['date'],
                         'hostname':item['computer']['hostname'],
                         'ip':((item['computer']['network_addresses'])[0]['ip']),
                         'mac':((item['computer']['network_addresses'])[0]['mac']),
                         'detection':item['detection'],
                         'disposition':item['file']['disposition'],
                         'file':(item['file']['identity']['sha256']),
                         'quarantine':'False',
                         'logged_in':logged_in,
                         'building':building,
                         'floor':floor,
                         'responder':responder
                         })

        #If the SHA is not in the threats_db, run it through Threatgrid to collect details about it.
        for sha in sha256s:
            if bool(threats_db.get(querydb.sha256 == sha)) == False:
                get_samples_from_threatgrid(sha)


def find_malware_events_from_cognitive():
    '''
    TAXII Client to pull indications of compromise from Cognitive Intelligence
    '''
    from random import randint
    import xml.dom.minidom

    timestamp_start = "2018-12-04T00:00:00+00:00"
    timestamp_end = "2018-12-06T00:00:00+00:00"

    message_id = randint(0,99999)

    url = "https://taxii.cloudsec.sco.cisco.com/skym-taxii-ws/PollService"

    payload = "<taxii_11:Poll_Request\n xmlns:taxii_11=\"http://taxii.mitre.org/messages/taxii_xml_binding-1.1\"\n message_id=\"%(id)s\"\n collection_name=\"%(feed)s\">\n <taxii_11:Exclusive_Begin_Timestamp>%(begin)s</taxii_11:Exclusive_Begin_Timestamp>\n <taxii_11:Inclusive_End_Timestamp>%(end)s</taxii_11:Inclusive_End_Timestamp>\n <taxii_11:Poll_Parameters allow_asynch=\"false\">\n <taxii_11:Response_Type>FULL</taxii_11:Response_Type>\n </taxii_11:Poll_Parameters>\n</taxii_11:Poll_Request>" % {"id":message_id, "feed":feed, "begin":timestamp_start, "end":timestamp_end}

    headers = {
    'Accept': "application/xml",
    'Content-Type': "application/xml",
    'X-Taxii-Content-Type': "urn:taxii.mitre.org:message:xml:1.1",
    'X-Taxii-Accept': "urn:taxii.mitre.org:message:xml:1.1",
    'X-Taxii-Services': "urn:taxii.mitre.org:services:1.1",
    'X-Taxii-Protocol': "urn:taxii.mitre.org:protocol:http:1.0",
    'cache-control': "no-cache"
    }

    response = requests.post(url, auth=(username, password), data=payload, headers=headers)

    print(response.text)

def quarantine_with_ise(mac_address):
    '''
    Leverages Adaptive Network Control on ISE to quarantine the devices with malware infection
    '''

    url = "https://%(ise_hostname)s:9060/ers/config/ancendpoint/apply" % {'ise_hostname':config['ise']['hostname']}

    payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ns0:operationAdditionalData xmlns:ns0=\"ers.ise.cisco.com\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">\n   <requestAdditionalAttributes>\n      <additionalAttribute name=\"macAddress\" value=\"%(mac)s\"/>\n      <additionalAttribute name=\"policyName\" value=\"KickFromNetwork\"/>\n   </requestAdditionalAttributes>\n</ns0:operationAdditionalData>" % {'mac':mac_address}

    headers = {
    'content-type': "application/xml",
    'accept': "application/json"
    }

    response = requests.request("PUT", url, data=payload, headers=headers, auth=(config['ise']['user'], config['ise']['password']), verify=False)

    hosts_db.update({'quarantine': 'True'}, querydb.mac == mac_address)

def unquarantine_with_ise(mac_address):
    '''
    Leverages Adaptive Network Control on ISE to unquarantine the devices after they have been quarantined.
    '''

    url = "https://%(ise_hostname)s:9060/ers/config/ancendpoint/clear" % {'ise_hostname':config['ise']['hostname']}

    payload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ns0:operationAdditionalData xmlns:ns0=\"ers.ise.cisco.com\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">\n   <requestAdditionalAttributes>\n      <additionalAttribute name=\"macAddress\" value=\"%(mac)s\"/>\n      <additionalAttribute name=\"policyName\" value=\"KickFromNetwork\"/>\n   </requestAdditionalAttributes>\n</ns0:operationAdditionalData>" % {'mac':mac_address}

    headers = {
    'content-type': "application/xml",
    'accept': "application/json"
    }

    response = requests.request("PUT", url, data=payload, headers=headers, auth=(config['ise']['user'], config['ise']['password']), verify=False)

    hosts_db.update({'quarantine': 'False'}, querydb.mac == mac_address)

def find_active_user_from_ise(ip_or_mac):
    '''
    Query ISE to determine the actively logged in user for affected devices.
    '''

    url = "https://%(ise_hostname)s:9060/ers/config/ancendpoint/apply" % {'ise_hostname':config['ise']['hostname']}

    headers= {
        'content-type': "application/xml",
        }

    response = requests.request("GET", url, headers=headers, auth=(config['ise']['user'], config['ise']['password']), verify=False)

    if(response.status_code == 200):
        root = ElementTree.fromstring(response.text)
        tree = ElementTree.ElementTree(root)

        for user in tree.findall('activeSession'):
            found_username="Not Found"
            if ((user.find('framed_ip_address').text == ip_or_mac ) or
                (user.find('calling_station_id').text == ip_or_mac )):
                found_username = user.find('user_name').text
                # print( "In loop, found active username: " + foundUsername )
                break
        return found_username
        # print("Found ISE active user: " + ISEactiveUser)
    else:
        print("An error has ocurred with the following code %(error)s" % {'error': response.status_code})

def get_host_location(mac):
    #Something
    print ()

def get_samples_from_threatgrid(sha256):
    '''
    Pull information about the identified malware from ThreatGrid.
    '''

    url = "https://panacea.threatgrid.com/api/v2/search/submissions"

    querystring = {"q":sha256,"api_key":config['threatgrid']['key']}


    headers = {
        'Cache-Control': "no-cache"
    }

    response = requests.request("GET", url, headers=headers, params=querystring)

    filenames = []
    magics = []
    sampleDomains= []

    for item in response.json()['data']['items']:
        samples = []
        if (item['item']['filename']) not in filenames:
            filenames.append(item['item']['filename'])
        if (item['item']['sample']) not in samples:
            samples.append(item['item']['sample'])
        if (item['item']['analysis']['metadata']['malware_desc'][0]['magic']) not in magics:
            magics.append(item['item']['analysis']['metadata']['malware_desc'][0]['magic'])
        threat_score = (item['item']['analysis']['threat_score'])
        for item in samples:
            collectedSamples = get_sample_domains_from_threatgrid(item)
            for domain in collectedSamples:
                if domain not in sampleDomains:
                    sampleDomains.append(domain)

    #wait 20 seconds in between VirusTotal queries since API limit is 4 per minute
    time.sleep(20)
    virustotal = get_virustotal_report(sha256)

    threats_db.insert({'sha256':sha256,
                       'magics':magics,
                       'threat_score':threat_score,
                       'filenames':filenames,
                       'domains':sampleDomains,
                       'virustotal':virustotal
                     })

def get_sample_domains_from_threatgrid(sample_id):
    '''
    Discovers a list of domains associated with a ThreatGrid Sample ID, obtained from querying the SHA256 hash.
    '''
    url = "https://panacea.threatgrid.com/api/v2/samples/feeds/domains"

    querystring = {"sample":sample_id,"after":"2018-10-01","api_key":config['threatgrid']['key']}

    headers = {
    'Cache-Control': "no-cache",
        }

    response = requests.request("GET", url, headers=headers, params=querystring)

    sampleDomains=[]

    #print(response.text)
    for item in response.json()['data']['items']:
        #print(item['domain'])
        sampleDomains.append(item['domain'])
    return (sampleDomains)

def get_investigate_security_scores(domain):

    url = "https://investigate.api.umbrella.com/security/name/" + domain

    headers = {
        'Authorization': "Bearer " + config['investigate']['key'],
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
    }

    response = requests.request("GET", url, headers=headers)

    scores = []

    scores.append(response.json()['dga_score'])
    scores.append(response.json()['perplexity'])
    scores.append(response.json()['securerank2'])
    scores.append(response.json()['pagerank'])
    scores.append(response.json()['asn_score'])
    scores.append(response.json()['prefix_score'])
    scores.append(response.json()['rip_score'])
    scores.append(response.json()['attack'])
    scores.append(response.json()['threat_type'])
    scores.append(response.json()['found'])

    return(scores)

def get_investigate_domain_score(domain):
    '''
    Takes a domain name and returns its Risk Score from Umbrella Investigate.
    '''

    url = "https://investigate.api.umbrella.com/domains/risk-score/" + domain

    headers = {
        'Authorization': "Bearer " + config['investigate']['key'],
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
    }

    response = requests.request("GET", url, headers=headers)

    return (response.json()['risk_score'])

def get_investigate_domains(domains):
    '''
    Gathers information about the domains associated with the indications of compromise discovered from Threat Grid.  This function returns the Content Category, Security Catogories, Risk Score (via investigateDomainScore(), and several other security metrics.  These are put into our "investigation" database.
    '''

    investigate_categories = { "0": "Adware", "1": "Alcohol", "2": "Auctions", "3": "Blogs", "4": "Chat", "5": "Classifieds", "6": "Dating", "7": "Drugs", "8": "Ecommerce/Shopping", "9": "File Storage", "10": "Gambling", "11": "Games", "12": "Hate/Discrimination", "13": "Health and Fitness", "14": "Humor", "15": "Instant Messaging", "16": "Jobs/Employment", "17": "Movies", "18": "News/Media", "19": "P2P/File sharing", "20": "Photo Sharing", "21": "Portals", "22": "Radio", "23": "Search Engines", "24": "Social Networking", "25": "Software/Technology", "26": "Television", "28": "Video Sharing", "29": "Visual Search Engines", "30": "Weapons", "31": "Webmail", "32": "Business Services", "33": "Educational Institutions", "34": "Financial Institutions", "35": "Government", "36": "Music", "37": "Parked Domains", "38": "Tobacco", "39": "Sports", "40": "Adult Themes", "41": "Lingerie/Bikini", "42": "Nudity", "43": "Proxy/Anonymizer", "44": "Pornography", "45": "Sexuality", "46": "Tasteless", "47": "Academic Fraud", "48": "Automotive", "49": "Forums/Message boards", "50": "Non-Profits", "51": "Podcasts", "52": "Politics", "53": "Religious", "54": "Research/Reference", "55": "Travel", "57": "Anime/Manga/Webcomic", "58": "Web Spam", "59": "Typo Squatting", "60": "Drive-by Downloads/Exploits", "61": "Dynamic DNS", "62": "Mobile Threats", "63": "High Risk Sites and Locations", "64": "Command and Control", "65": "Command and Control", "66": "Malware", "67": "Malware", "68": "Phishing", "108": "Newly Seen Domains", "109": "Potentially Harmful", "110": "DNS Tunneling VPN", "111": "Arts", "112": "Astrology", "113": "Computer Security", "114": "Digital Postcards", "115": "Dining and Drinking", "116": "Dynamic and Residential", "117": "Fashion", "118": "File Transfer Services", "119": "Freeware and Shareware", "120": "Hacking", "121": "Illegal Activities", "122": "Illegal Downloads", "123": "Infrastructure", "124": "Internet Telephony", "125": "Lotteries", "126": "Mobile Phones", "127": "Nature", "128": "Online Trading", "129": "Personal Sites", "130": "Professional Networking", "131": "Real Estate", "132": "SaaS and B2B", "133": "Safe for Kids", "134": "Science and Technology", "135": "Sex Education", "136": "Social Science", "137": "Society and Culture", "138": "Software Updates", "139": "Web Hosting", "140": "Web Page Translation", "141": "Organisation Email", "142": "Online Meetings", "143": "Paranormal", "144": "Personal VPN", "145": "DIY Projects", "146": "Hunting", "147": "Military", "150": "Cryptomining"}

    url = "https://investigate.api.umbrella.com/domains/categorization/"
    payload = domains
    headers = {
        'Authorization': "Bearer " + config['investigate']['key'],
        'Content-Type': "application/json",
        'Cache-Control': "no-cache"
    }

    response = requests.request("POST", url, data=payload, headers=headers)

    for item in response.json():

        content_cat = []
        security_cat = []
        scores = get_investigate_security_scores(item)
        content = (response.json()[item]['content_categories'])
        security = (response.json()[item]['security_categories'])

        for category in content:
            content_cat.append(investigate_categories[category])

        for category in security:
            security_cat.append(investigate_categories[category])

        if bool(domains_db.get(querydb.domain == item)) == False:
            hosts_db.insert({'domain':item,
                           'domain_score':get_investigate_domain_score(item),
                           'dga_score':scores[0],
                           'perplexity':scores[1],
                           'securerank2':scores[2],
                           'pagerank':scores[3],
                           'asn_score':scores[4],
                           'prefix_score':scores[5],
                           'rip_score':scores[6],
                           'attack':scores[7],
                           'threat_type':scores[8],
                           'found':scores[9],
                           'content_cat':content_cat,
                           'security_cat':security_cat
                          })

def block_with_umbrella(domain_name):
    '''
    Creates a new custom block entry with Umbrella Enforcement.
    '''
    date = datetime.datetime.now().replace(microsecond=0).isoformat()
    url = "https://s-platform.api.opendns.com/1.0/events"

    querystring = {"customerKey":config['umbrella']['key']}

    payload = '''[\n
                 {\n    \"alertTime\": \"%(date)s.0Z\",
                  \n    \"deviceId\": \"ba6a59f4-e692-4724-ba36-c28132c761de\",
                  \n    \"deviceVersion\": \"13.7a\",
                  \n    \"dstDomain\": \"%(domain_name)s\",
                  \n    \"dstUrl\": \"http://%(domain_name)s/\",
                  \n    \"eventTime\": \"%(date)s.0Z\",
                  \n    \"protocolVersion\": \"1.0a\",
                  \n    \"providerName\": \"Security Platform\"
                  \n    }\n]''' % {"date":date, "domain_name":domain_name}

    headers = {
        'Content-Type': "application/json"
        }

    response = requests.request("POST", url, data=payload, headers=headers, params=querystring)

    print(response.text)

def list_blocked_domains_from_umbrella():
    '''
    Lists all customer blocked domains with Umbrella Enforcement.
    '''
    blocked_domains = []
    url = "https://s-platform.api.opendns.com/1.0/domains"

    querystring = {"customerKey":config['umbrella']['key']}

    headers = {
        'Content-Type': "application/json"
        }

    response = requests.request("GET", url, headers=headers, params=querystring)

    for domain in response.json()["data"]:
        blocked_domains.append(domain["name"])

    return(blocked_domains)

def get_virustotal_report(sha):
    params = {'apikey': config['virustotal']['public_api'], 'resource': sha}
    headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip,  My Python requests library example client or username"}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
    json_response = response.json()

    detected = {}

    if (json_response['response_code'] == 0):
        result = {'link': 'Threat Not Found in VirusTotal', 'total': '0', 'positives': '0', 'detecting': detected}
        return (result)
    else:
        for item in json_response['scans']:
            if (json_response['scans'][item]['detected'] == True):
                detected.update({item: json_response['scans'][item]['result']})
        result = {'link': json_response['permalink'], 'total': json_response['total'], 'positives': json_response['positives'], 'detecting': detected}
        return (result)

def create_servicenow_incident():
    '''
    Creates a new incident in the ServiceNow ITSM to coordinate enterprise-wide tracking and response.
    '''

    timestamp = int(datetime.datetime.now().timestamp())
    time = datetime.datetime.now()
    formatted_time = time.strftime("%Y-%m-%d %H:%M")

    url = "https://%(sn_host)s/api/now/v1/table/incident" % {'sn_host': config['servicenow']['hostname']}
    headers = {"Content-Type":"application/json","Accept":"application/json","Authorization":"Basic %(auth)s" % {"auth":config['servicenow']['basic']}}
    payload = '''{\n    \"caller_id\": \"IR Flow\",
                  \n    \"short_description\": \"Incident From %(date)s\",
                  \n    \"description\": \"Incident Response Activity\",
                  \n    \"assigned_to\": \"Security Team\",
                  \n    \"impact\": \"2\",
                  \n    \"urgency\": \"1\"\n}''' % {"date":formatted_time}

    response = requests.request("POST", url, data=payload, headers=headers)

    if response.status_code != 201:
        print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:',response.json())
        exit()
    data = response.json()
    ticket = data["result"]["number"]

    return(ticket)

def create_new_webex_teams_incident_room(incident, ticket):
    '''
    Creates a new Webex team room and populates it with the details of the incident from the incident report in the tool.
    '''

    webex_teams = ciscosparkapi.CiscoSparkAPI(config['webex_teams']['token'])
    incident_room = webex_teams.rooms.create("Security Incident %(incident)s" % {'incident': ticket})
    md = '''
    ## New Incident %(incident)s

    Patient Zero

    Computer Name: %(computer)s

    Logged-in User: %(username)s

    Host IP Address: %(hosts)s

    ServiceNow Link: https://%(sn_host)s/nav_to.do?uri=incident.do?sysparm_query=number=%(incident)s

    ''' % {'incident':ticket, 'computer':incident['computer_name'], 'username':incident['username'], 'hosts':incident['host_ip_addresses'], 'sn_host':config['servicenow']['hostname']}
    message = webex_teams.messages.create(incident_room.id, markdown = md, files = ['./Incident Report.txt'])
    return (incident_room.id)

if __name__ == '__main__':
    import os
    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    app.run(HOST, PORT, debug=True)

'''
#Start the App

if __name__ == "__main__":
    testing()
'''
