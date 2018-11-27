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
* [Cisco Threat Intelligence Director](https://www.cisco.com/c/en/us/td/docs/security/firepower/622/configuration/guide/fpmc-config-guide-v622/threat_intelligence_director_tid.pdf)
* [Firepower Management Center/Firepower Threat Defense](https://www.cisco.com/c/en/us/products/security/firewalls/index.html)
* [Webex Teams](https://www.webex.com/products/teams/index.html)

and third-party tools including:

* [VirusTotal](https://www.virustotal.com/)
* [ITSM Ticketing System, such as Remedy or Zendesk](http://www.bmc.com/it-solutions/remedy-itsm.html)

A stretch goal of this sprint is to add a physical incident response flow which will leverage:

* [Catalyst 9000-series](https://www.cisco.com/c/en/us/products/switches/catalyst-9000.html)
* [Wireless LAN Controllers and Access Points](https://www.cisco.com/c/en/us/products/wireless/wireless-lan-controller/index.html)
* [CMX Dectect and Locate - Real Time Location Services](https://www.cisco.com/c/en/us/solutions/enterprise-networks/connected-mobile-experiences/index.html)
* [DNA Center](https://www.cisco.com/c/en/us/products/cloud-systems-management/dna-center/index.html)
* [Meraki Scanning (Location Services)](https://meraki.cisco.com/technologies/location-analytics)

## Team Members

* Brian Sak <brsak@cisco.com> - APO
* Eddie Mendonca <eddiem@cisco.com> - GSSO
* One more team member, unconfirmed at time of initial submission.


## Solution Components


This python project primarily uses the Cisco Security APIs to gather indications of compromise, information about the associated threats, and enforce policy.  Underneath the hood it uses a Flask/Jinja2 framework, utilizing the Cisco UI Kit, for UX and TinyDB to store the results of API calls to minimize the number of calls and reduce latency of loading information.  The incident response tool also feeds the incident report into both Webex Teams and into an ITSM ticketing system to track the incident through its lifecycle and coordinate response from multiple teams.

## Usage

<!-- This does not need to be completed during the initial submission phase  

Provide a brief overview of how to use the solution  -->



## Installation

git clone https://wwwin-github.cisco.com/brsak/irflow.git  <br>
pip install -r requirements.txt <br>
python ./app.py

## Documentation

Documentation and video demonstration coming soon.

## License

Provided under Cisco Sample Code License, for details see [LICENSE](./LICENSE.md)

## Code of Conduct

Our code of conduct is available [here](./CODE_OF_CONDUCT.md)

## Contributing

See our contributing guidelines [here](./CONTRIBUTING.md)
