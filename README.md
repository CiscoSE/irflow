# irflow

Incident Response Workflow leveraging Cisco security.


## Business/Technical Challenge

With security response, time is your enemy.  It's during this time between compromise and remediation that potentially allows the threat to spread, data to be exfiltrated, or other hosts to encounter the same source of infedtion.  

## Proposed Solution

This app puts time back on the side of the responder.  It allows them to quickly identify threats, investigate them, contain them, and limit additional threats from impacting their organization.

This application will aid security operations teams and incident responders by quickly identifying compromised hosts and allowing them to be segmented to contain the malware or lateral movement. It also allows the responder to investigate the source of the infection using Cisco technologies and threat information.  Finally, it can limit future exposres to those, or similar threats. 


### Cisco Products Technologies/ Services

Our solution will levegerage the following Cisco technologies:

* [Umbrella Investigate](https://umbrella.cisco.com/products/features)
* [Umbrella Enforcement](https://umbrella.cisco.com/products/features)
* [AMP for Endpoints](https://www.cisco.com/c/en/us/products/security/amp-for-endpoints/index.html)
* [Threat Grid](https://www.cisco.com/c/en/us/products/security/threat-grid/index.html)
* [Identity Services Engine](https://www.cisco.com/c/en/us/products/security/identity-services-engine/index.html)
* [Cognitive Intelligence](https://www.cisco.com/c/en/us/products/security/cognitive-threat-analytics/index.html)
* [Firepower Management Center/Firepower Threat Defense](https://www.cisco.com/c/en/us/products/security/firewalls/index.html)

and third-party tools including:

* [VirusTotal](https://www.virustotal.com/)

## Team Members

* Brian Sak <brsak@cisco.com> - APO
* Eddie Mendonca <eddiem@cisco.com> - GSSO


## Solution Components


This python project primarily uses the Cisco security APIs to gather threat information and enforce policy.  Underneath the hood it uses a Flask/Jinja2 framework, utilizing the Cisco UI Kit, for UX and TinyDB to store the results of API calls to minimize the number of calls and reduce latency of loading information.

## Usage

<!-- This does not need to be completed during the initial submission phase  

Provide a brief overview of how to use the solution  -->



## Installation

git clone https://wwwin-github.cisco.com/brsak/irflow.git  <br>
pip install -r requirements.txt
python ./app.py

## Documentation

Documentation and video demonstration coming soon.

## License

Provided under Cisco Sample Code License, for details see [LICENSE](./LICENSE.md)

## Code of Conduct

Our code of conduct is available [here](./CODE_OF_CONDUCT.md)

## Contributing

See our contributing guidelines [here](./CONTRIBUTING.md)
