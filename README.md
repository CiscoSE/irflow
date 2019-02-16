# irflow

A Coordinated and Automated Incident Response Workflow Leveraging Cisco Security.


## Business/Technical Challenge

When a security incident happens, time is your enemy.  It's during this time between compromise and remediation that potentially allows the threat to spread, data to be exfiltrated, or other hosts to encounter the same source of infection.  Incident responders typically will need to query multiple dashboards, various sources of threat information, and struggle to coordinate between all teams when responding to an incident.

## Proposed Solution

This app puts time back on the side of the responder.  It allows them to quickly identify confirmed threats, investigate them, contain them, and limit additional threats from impacting their organization.  In addition, it puts all of the tools required during the incident response lifecycle in one interface and harnesses the power of Cisco's secure architecture.

This application will aid security operations teams and incident responders by quickly identifying compromised hosts and allowing them to be segmented to contain the malware or lateral movement. It also allows the responder to investigate the source of the infection using Cisco technologies and threat information and can limit future exposures to those, or similar threats. Finally, it centralized communication about the incident so it can be tracked and muliple teams can coordinate efforts.


### Cisco Products Technologies/ Services

Our solution will leverage the following Cisco technologies:

* [Umbrella Investigate](https://umbrella.cisco.com/products/features)
* [Umbrella Enforcement](https://umbrella.cisco.com/products/features)
* [AMP for Endpoints](https://www.cisco.com/c/en/us/products/security/amp-for-endpoints/index.html)
* [Threat Grid](https://www.cisco.com/c/en/us/products/security/threat-grid/index.html)
* [Identity Services Engine](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html)
* [Cognitive Intelligence](https://www.cisco.com/c/en/us/products/security/cognitive-threat-analytics/index.html)
* [Cisco Threat Response](https://www.cisco.com/c/en/us/products/security/threat-response.html)
* [Webex Teams](https://www.webex.com/products/teams/index.html)
* [CMX Dectect and Locate - Real Time Location Services](https://www.cisco.com/c/en/us/solutions/enterprise-networks/connected-mobile-experiences/index.html)

and third-party tools including:

* [VirusTotal](https://www.virustotal.com/)
* [ServiceNow ITSM](https://www.servicenow.com/products/it-service-management.html)

## Team Members

* Brian Sak <brsak@cisco.com> - APO
* Eddie Mendonca <eddiem@cisco.com> - GSSO
* Paul Marsh <pmarsh@cisco.com> - USPO


## Solution Components


This python project primarily uses the Cisco Security APIs to gather indications of compromise, information about the associated threats, and enforce policy.  Underneath the hood it uses a Flask/Jinja2 framework, utilizing the Cisco UI Kit, for UX and TinyDB to store the results of API calls to minimize the number of calls and reduce latency of loading information.  The incident response tool also feeds the incident report into both Webex Teams and into an ITSM ticketing system to track the incident through its lifecycle and coordinate response from multiple teams.

## Usage

<!-- This does not need to be completed during the initial submission phase  

Provide a brief overview of how to use the solution  -->



## Installation

git clone https://github.com/CiscoSE/irflow.git  <br>
pip install -r requirements.txt <br>
edit config.sample.yml with your API keys and credentials <br>
rename config.sample.yml to config.yml <br>
python ./app.py (web interface) or python ./headless.py (service)

## Documentation and Demonstration

A video demonstration of this project can be found at https://sharevideo.cisco.com/#/videos/4cb83daf-5db1-4bf8-bc9a-48094a3fd17a (Cisco Internal) or https://youtu.be/KwFILkVnbEo (public) <br>

The web interface relies on three databases that are populated with details from the API calls: threats_db.json, domains_db.json, and hosts_db.json. Running the headless script first will create and populate these databases.  After initial creation, you can use the web interface and it will display the collected data.  The headless script will continue to add new IOCs and associated details to the databases on an hourly basis when it is running or can be triggered on demand to gather new details. <br>

The web interface runs on a localized instance on port 5555.  After running app.py, you can access the web interface using http://localhost:5555. <br>

Currently, the app requires AMP4E, Investigate, Threat Grid, and Umbrella at a minimum to operate.  ISE is required for user details and threat response and Webex Teams and ServiceNow are required for the incident report functionality. Cognitive Intelligence, Firepower, Cisco Threat Response, and CMX are optional and can omitted with minimal changes to the code.

Features:

Threat Investigation - Lists the IOCs and details about impacted hosts.  Clicking on the hostname reveals additional details about logged in users, host location, and site contact. <br>

Threat Response - Allows you to initiate an Rapid Threat Response action against an identified threat.  The host will be quarantined from ISE using the ANC feature. <br>

Threat Research - Provides additional details from Threat Grid and Umbrella Investigate using the threat (SHA256) as a query term. <br>

Incident Reports - Populated by the investigator, this form will be included with the creation of a new Webex Teams room and will trigger the creation of a service ticket in ServiceNow. <br>

Settings (gear icon) - Add or update any of the fields from the config.yml file. <br>

Search (magnifying glass icon) - Search the database for a MAC, IP or SHA256.

## License

Provided under Cisco Sample Code License, for details see [LICENSE](./LICENSE.md)

## Code of Conduct

Our code of conduct is available [here](./CODE_OF_CONDUCT.md)

## Contributing

See our contributing guidelines [here](./CONTRIBUTING.md)
