Supporting add-on for Open Threat Exchange
-----------------------------------------

This app integrates OTX indicators collected by TA-otx into the Splunk Enterprise Security threat intelligence framework.

It does this within a modular input otx_intel_manager which periodically reads the data that has been collected by TA-otx and pushes it into the threat collections in a correctly structured manner.

Requirements
============

* TA-otx -- This needs to be collecting OTX data, but is not a search time requirement for this add-on
* Splunk for Enterprise Security

Setup
=====
To set up this app after install:
1. Ensure that you have OTX data collected by TA-otx and it is fully backfilled to where you want it
1. Enable the otx_intel_manager://default modular input

The first backfill may take some time and can use CPU on your ES search head, depending upon how many OTX indicators you have indexed and are backfilling.

Field mapping
=============
Currently evaluated indicator types from OTX are:

* domain
* hostname
* email
* FileHash-*
* URL
* IPv4
* IPv6

These map to threat intel groups and fields in Splunk ES according to the mapping that can be found in `bin/otx_intel_manager.py` (search for the `type_mappings` function)

Other field mappings that are important:

* A concatenation of OTX tags, targeted industries and targeted countries map to `threat_category`
* OTX adversary maps to `threat_group`
* The `description` in the Splunk `threat_group_intel` collection is composed of both the pulse name and description from OTX
* The `source_path` is the URL to view the pulse in detail in OTX

Expiration
==========
There are a set of disabled saved searches called `OTX <intel collection> - Retention` included. When enabled, these will run overnight and remove any indicator older than 365 days. The exact length of retention can be tuned by modifying the `otx_threat_expiry` macro.
