Supporting add-on for Open Threat Exchange
-----------------------------------------

This app integrates OTX indicators collected by TA-otx into the Splunk ES threat feeds

It does this by running a saved search to populate the various otx_*_intel lookups with the last 90 days of OTX indicators. These lookups are then setup as threat sources for Splunk ES.

The `otx_index` macro controls where this add-on will look for `otx:indicator` events.

Requirements:

* TA-otx -- This needs to be collecting OTX data, but is not a search time requirement for this add-on
* Splunk for Enterprise Security

This app itself should require no setup if Splunk ES is already working, and OTX data is available.

Supported indicator types from OTX are:

* domain
* hostname
* email
* FileHash-*
* URL
* IPv4
* IPv6
