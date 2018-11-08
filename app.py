"""
irflow - Incident Response Workflow

This app enables security operations or an incident responder to leverage the Cisco security applications and tools to quickly assess hosts that have been compromised and respond by isolating them from the network.  In addition, the responder can identify malicious sources of information and use Umbrella and Firepower to block them, preventing other hosts from potential compromise from known malicious sources.

Script Dependencies:
    requests
    datetime
    getpass
    tinydb
    pprint
    flask

Depencency Installation:
    $ pip install -r requirements.txt

Copyright (c) 2018, Cisco Systems, Inc. All rights reserved.
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
"""

import requests # import requests library
try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

import datetime #import datetime for ISO 8601 timestamps
import getpass  #import getpass to mask password entries
from tinydb import TinyDB,Query
from pprint import pprint #import Pretty Print for formated text output
from flask import Flask  #import web application
import ciscosparkapi #Webex Teams features for creating rooms


app = Flask(__name__)
wsgi_app = app.wsgi_app
from routes import *


#Import Variables from config.py
from config import amp4e_client_id
from config import amp4e_computer
from config import amp4e_api_key
from config import ise_username
from config import ise_password
from config import ise_host
from config import threatgrid_key
from config import threatgrid_host
from config import investigate_token
from config import umbrella_key
from config import umbrella_secret
from config import webex_teams_access_token

#Initialize database for storing data locally
hosts_db = TinyDB('hosts_db.json')
threats_db = TinyDB('threats_db.json')
domains_db = TinyDB('domains_db.json')
querydb = Query()

def main():
    #investigateSecurity("bing.com", investigate_token)
    #investigateDomains("[\"www.bing.com\",\"github.com\",\"www.bing.com\",\"codeload.github.com\",\"7tno4hib47vlep5o.tor2web.fi\"]", investigate_token)
    #getSamplesFromTG(threatgrid_host,threatgrid_key,"ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
    print ('Starting...')
    #findMalwareEventsFromCTA()
    #findMalwareEvents(amp4e_client_id, amp4e_api_key)
    #incident_room = create_new_webex_teams_incident_room(webex_teams_access_token)
    #attach_incident_report(webex_teams_access_token, incident_room)

def findMalwareEventsFromAMP(amp4e_client_id, amp4e_api_key):
    '''
    Identifies indications of compromise from AMP for Endpoints.  Itemizes all hosts where AMP identifies malware was successfully executed
    '''

    url = "https://" + amp4e_client_id + ":" + amp4e_api_key + "@api.amp.cisco.com/v1/events"
    querystring = {"event_type[]":"1107296272"}

    headers = {
    'Cache-Control': "no-cache",
    }

    #print(hosts_db.search(hosts_db_query.hostname == 'host1'))

    response = requests.request("GET", url, headers=headers, params=querystring)

    for item in response.json()['data']:

        hosts_db.insert({'date':item['date'],
                         'hostname':item['computer']['hostname'],
                         'ip':((item['computer']['network_addresses'])[0]['ip']),
                         'mac':((item['computer']['network_addresses'])[0]['mac']),
                         'detection':item['detection'],
                         'disposition':item['file']['disposition'],
                         'file':(item['file']['identity']['sha256']),
                         'quarantined':'false'
                         })

def nukeFromSpace(iseuser, isepassword, mac_address = "66:96:a5:94:76:32"):
    '''
    Leverages Adaptive Network Control on ISE to quarantine the devices with malware infection
    '''

    url = "https://" + ise_username + ":" + ise_password + "@" + ise_host + "/ers/config/ancendpoint/apply"

    payload = { "OperationAdditionalData": {
                "additionalData": [{
                "name": "macAddress",
                "value": mac_address
               },
               {
                "name": "policyName",
                 "value": "ANC-KickFromNetwork"
                }]
               }
               }
    headers = {
    'Content-Type': "application/json",
    'Accept': "application/json",
    'Cache-Control': "no-cache"
    }

    response = requests.request("PUT", url, data=payload, headers=headers)

    hosts_db.update({'quarantine': 'true'}, querydb.mac == mac_address)
    print(response.text)

def unnukeFromSpace(iseuser, isepassword, mac_address = "66:96:a5:94:76:32"):
    '''
    Leverages Adaptive Network Control on ISE to unquarantine the devices after they have been quarantined.
    '''

    url = "https://" + ise_username + ":" + ise_password + "@" + ise_host + "/ers/config/ancendpoint/clear"

    payload = { "OperationAdditionalData": {
                "additionalData": [{
                "name": "macAddress",
                "value": mac_address
               },
               {
                "name": "policyName",
                 "value": "ANC-KickFromNetwork"
                }]
               }
               }
    headers = {
    'Content-Type': "application/json",
    'Accept': "application/json",
    'Cache-Control': "no-cache"
    }

    response = requests.request("PUT", url, data=payload, headers=headers)

    hosts_db.update({'quarantine': 'false'}, querydb.mac == mac_address)
    print(response.text)

def getSamplesFromTG(threatgrid_host,threatgrid_key,sha256):
    '''
    Pull information about the identified malware from ThreatGrid.
    '''

    url = "https://" + threatgrid_host + "/api/v2/search/submissions"

    querystring = {"q":sha256,"api_key":threatgrid_key}


    headers = {
        'Cache-Control': "no-cache"
    }

    response = requests.request("GET", url, headers=headers, params=querystring)

    #print(response.text)

    filenames = []
    magics = []
    sampleDomains= []

    for item in response.json()['data']['items']:
        samples = []
        if (item['item']['filename']) not in filenames:
            filenames.append(item['item']['filename'])
        if (item['item']['sample']) not in samples:
            samples.append(item['item']['sample'])
        #print(item['item']['filename'])
        if (item['item']['analysis']['metadata']['malware_desc'][0]['magic']) not in magics:
            magics.append(item['item']['analysis']['metadata']['malware_desc'][0]['magic'])
        threat_score = (item['item']['analysis']['threat_score'])
        for item in samples:
            collectedSamples = getSampleDomainsFromTG(threatgrid_host,threatgrid_key,item)
            for domain in collectedSamples:
                if domain not in sampleDomains:
                    sampleDomains.append(domain)

    threats_db.insert({'sha256':sha256,
                       'magics':magics,
                       'threat_score':threat_score,
                       'filenames':filenames,
                       'domains':sampleDomains
                     })

def getSampleDomainsFromTG(threatgrid_host, threatgrid_key, sample_id):
    '''
    Discovers a list of domains associated with a ThreatGrid Sample ID, obtained from querying the SHA256 hash.
    '''
    url = "https://" + threatgrid_host + "/api/v2/samples/feeds/domains"

    querystring = {"sample":sample_id,"after":"2018-02-01","api_key":threatgrid_key}

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

def investigateDomains(domains,investigate_token):
    '''
    Gathers information about the domains associated with the indications of compromise discovered from Threat Grid.  This function returns the Content Category, Security Catogories, Risk Score (via investigateDomainScore(), and several other security metrics.  These are put into our "investigation" database.
    '''
    
    from config import investigate_categories
    

    url = "https://investigate.api.umbrella.com/domains/categorization/"
    payload = domains
    headers = {
        'Authorization': "Bearer " + investigate_token,
        'Content-Type': "application/json",
        'Cache-Control': "no-cache"
    }

    response = requests.request("POST", url, data=payload, headers=headers)

    for item in response.json():
        
        content_cat = []
        security_cat = []
        scores = investigateSecurity(item,investigate_token)
        content = (response.json()[item]['content_categories'])
        security = (response.json()[item]['security_categories'])
        for category in content:
            content_cat.append(investigate_categories[category])
        for category in security:
            security_cat.append(investigate_categories[category])
        domains_db.insert({'domain':item,
                         'domain_score':(investigateDomainScore(item,investigate_token)),
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
                         'security':security_cat
                         })

def investigateDomainScore(domain,investigate_token):
    '''
    Takes a domain name and returns its Risk Score from Umbrella Investigate.
    '''

    url = "https://investigate.api.umbrella.com/domains/risk-score/" + domain

    headers = {
        'Authorization': "Bearer " + investigate_token,
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
    }

    response = requests.request("GET", url, headers=headers)

    return (response.json()['risk_score'])

def investigateSecurity(domain, investigate_token):

    url = "https://investigate.api.umbrella.com/security/name/" + domain

    headers = {
        'Authorization': "Bearer " + investigate_token,
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

def findMalwareEventsFromCTA():

    import requests

    url = "https://taxii.cloudsec.sco.cisco.com/skym-taxii-ws/PollService/"

    payload = "<taxii_11:Poll_Request \n    xmlns:taxii_11=\"http://taxii.mitre.org/messages/taxii_xml_binding-1.1\"\n    message_id=\"96485\"\n    collection_name=\"WEBFLOWS_CTA6551672149651114470_V3\">\n    <taxii_11:Exclusive_Begin_Timestamp>2018-09-01T00:00:00Z</taxii_11:Exclusive_Begin_Timestamp>\n    <taxii_11:Inclusive_End_Timestamp>2018-09-30T12:00:00Z</taxii_11:Inclusive_End_Timestamp>\n    <taxii_11:Poll_Parameters allow_asynch=\"false\">\n        <taxii_11:Response_Type>FULL</taxii_11:Response_Type>\n    </taxii_11:Poll_Parameters>\n</taxii_11:Poll_Request>"
    headers = {
    'X-TAXII-Content-Type': "urn:taxii.mitre.org:protocol:http:1.0",
    'X-TAXII-Services': "urn:taxii.mitre.org:services:1.1",
    'X-TAXII-Protocol': "urn:taxii.mitre.org:message:xml:1.1",
    'Content-Type': "application/xml; charset=UTF-8",
    'Authorization': "Basic dGF4aWktMWYzNWIzOWMtOGU4Ni00OWNiLWFkYzMtNzE1NmMxY2M1N2YzOnhiRHJlV1A1aWxMOVBKUWJIYzdhNzFMMTIxaGVuU2F0bXBESXpMRVdGZ21uWXdCTg==",
    'Cache-Control': "no-cache",
    }

    response = requests.request("POST", url, data=payload, headers=headers)

    print(response.text)

def blockWithUmbrella(domain,umbrella_key):
    import requests

    url = "https://s-platform.api.opendns.com/1.0/events"

    querystring = {"customerKey":umbrella_key}

    payload = [{"alertTime":datetime.datetime.now().isoformat(),
                "deviceId":"ba6a59f4-e692-4724-ba36-c28132c761de",
                "deviceVersion":"13.7a",
                "dstDomain":domain,
                "dstUrl":"http://" + domain + "/",
                "eventTime":datetime.datetime.now().isoformat(),
                "protocolVersion":"1.0a",
                "providerName":"Security Platform"}]
    headers = {
        'Content-Type': "application/json",
        'Cache-Control': "no-cache",
        }

    response = requests.request("POST", url, data=payload, headers=headers, params=querystring)

    print(response.text)

def create_new_webex_teams_incident_room(webex_teams_access_token):
    webex_teams = ciscosparkapi.CiscoSparkAPI(webex_teams_access_token)
    timestamp = datetime.datetime.now().timestamp()
    time = datetime.datetime.now().isoformat()
    incident_room = webex_teams.rooms.create("Incident %(incident)s Room Created %(time)s" % {'incident': timestamp, 'time': time})
    return (incident_room.id)

def attach_incident_report(webex_teams_access_token, incident_room):
    #incident_room = "Y2lzY29zcGFyazovL3VzL1JPT00vY2Q0MWNjMzAtZTM4Zi0xMWU4LWE1ZDItZjFkOTJhNmJmNGI3"
    webex_teams = ciscosparkapi.CiscoSparkAPI(webex_teams_access_token)
    message = webex_teams.messages.create(incident_room, text = "Test")

if __name__ == '__main__':
    import os
    HOST = os.environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(os.environ.get('SERVER_PORT', '5555'))
    except ValueError:
        PORT = 5555
    app.run(HOST, PORT, debug=True)

#Start the App

'''
if __name__ == "__main__":
    main()
'''