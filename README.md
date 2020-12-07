Supporting add-on for Open Threat Exchange
-----------------------------------------

This app integrates OTX indicators collected by TA-otx into the Splunk Enterprise Security threat intelligence framework.

It does this with a series of saved searches running (by default) every 12 hours. Previous versions of this app used a modular input to do this: this input is no longer required and should be disabled if you still have it in your system.

Requirements
============

* TA-otx -- This needs to be collecting OTX data, but there is not a requirement for this add-on on the Splunk ES search head
* Splunk for Enterprise Security

Setup
=====
To set up this app after install:
1. Ensure that you have OTX data collected by TA-otx and it is fully backfilled to where you want it
1. Customise the macro `otx_index` to point to where your OTX data is 
1. (Optional) Customise the `otx_lookback` macro if you wish more/less than 90 days of indicators included
1. (Optional) Customise the schedule of all saved searches if you wish more frequent updates

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
* CIDR

These map to the equivalent threat intel groups and fields in Splunk ES.

Other field mappings that are important:

* A concatenation of OTX tags, targeted industries and targeted countries map to `threat_category`
* OTX adversary maps to `threat_group`
* The `description` in the Splunk `threat_group_intel` collection is composed of both the pulse name and description from OTX
* The `source_path` is the URL to view the pulse in detail in OTX

Expiration
==========
There are a set of disabled saved searches called `OTX <intel collection> - Retention` included. When enabled, these will run overnight and remove any indicator older than 365 days. The exact length of retention can be tuned by modifying the `otx_threat_expiry` macro.
