Supporting add-on for Open Threat Exchange
-----------------------------------------

This app integrates OTX indicators collected by TA-otx into the Splunk ES threat feeds

It does this within a modular input otx_intel_manager which periodically reads the data that has been collected by TA-otx and pushes it into the threat collections in a structured manner.

Requirements:

* TA-otx -- This needs to be collecting OTX data, but is not a search time requirement for this add-on
* Splunk for Enterprise Security

To set up this app after install:
1. Ensure that you have OTX data collected by TA-otx and it is fully backfilled to where you want it
1. Enable the otx_intel_manager://default modular input

The first backfill may take some time and use CPU on your ES search head, depending upon how many OTX indicators you have indexed.

Currently used indicator types from OTX are:

* domain
* hostname
* email
* FileHash-*
* URL
* IPv4
* IPv6

These map to threat intel groups and fields in Splunk ES according to the mapping that can be found in bin/otx_intel_manager.py (search for type_mappings)

Other mappings that are important:

* OTX tags map to threat_category
* OTX adversary maps to threat_group
* The description in the Splunk threat intel is composed of the pulse name and description from OTX
