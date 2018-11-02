import sys
import os
import hashlib
import time
import json
import urllib
from collections import defaultdict

from splunklib.modularinput import *
from splunklib.six.moves.urllib.parse import urlsplit
import splunklib.client as client
import splunklib.results as results

class OTXIntelManagerModularInput(Script):

	def get_scheme(self):
		scheme = Scheme("Open Threat Exchange Intel Manager")
		scheme.description = "Integrate OTX pulses into the Splunk ES Threat Intelligence framework"
		scheme.use_external_validation = False
		scheme.use_single_instance = False

		otx_index = Argument("otx_index")
		otx_index.data_type = Argument.data_type_string
		otx_index.title = "OTX index"
		otx_index.description = "The index in which we will look to find the OTX events"
		otx_index.required_on_create = True
		otx_index.required_on_edit = True
		scheme.add_argument(otx_index)

		backfill_days = Argument("backfill_days")
		backfill_days.data_type = Argument.data_type_number
		backfill_days.title = "Backfill days"
		backfill_days.description = "The number of days to backfill indicators for on first run"
		backfill_days.required_on_create = True
		backfill_days.required_on_edit = True
		scheme.add_argument(backfill_days)

		return scheme

	def stream_events(self, inputs, ew):

		BATCH_SIZE = 50

		for input_name, input_item in inputs.inputs.iteritems():

			otx_index = str(input_item["otx_index"])
			backfill_days = int(input_item["backfill_days"])
			run_time = time.time()

			ew.log(ew.INFO, "Beginning scan of index %s for OTX threat intel" % otx_index)

			try:
				checkpoint_data = self.get_checkpoint_data(inputs.metadata["checkpoint_dir"], input_name)
			except IOError:
				checkpoint_data = None

			# Try to load the last ran date from the checkpoint data
			if checkpoint_data is not None and 'last_ran' in checkpoint_data:
				last_ran = checkpoint_data['last_ran']
			else:
				last_ran = None

		 	if last_ran is not None:
		 		et = last_ran
		 	else:
				et = run_time - (backfill_days*24*3600)

			# We look back and extra week for indicators/pulses, but their _indextime must be < et
			# This is to work around race condition issues with data arriving from the API
			et_safe = et - (7*24*3600)

			# Get a service handle back to splunkd
			splunkd_uri = self._input_definition.metadata["server_uri"]
			session_key = self._input_definition.metadata["session_key"]
			splunkd = urlsplit(splunkd_uri, allow_fragments=False)
			service = client.Service(
			    scheme=splunkd.scheme,
			    host=splunkd.hostname,
			    port=splunkd.port,
			    token=session_key,
				owner="nobody"
			)

			indicator_query = "search index=%s earliest=%d _indextime>%d latest=%d sourcetype=otx:indicator | fields _time type indicator pulse_id" % (otx_index, et_safe, et, run_time)

			ew.log(ew.INFO, "Fetching indicators...")

			indicator_results = service.jobs.oneshot(indicator_query, count=0)
			indicator_reader = results.ResultsReader(indicator_results)

			indicator_batches = defaultdict(list)

			indicator_count_total = 0
			indicator_count_mapped = 0
			type_mappings = self.get_type_mappings()

			for indicator in indicator_reader:
				indicator_count_total = indicator_count_total + 1
				if indicator['type'] in type_mappings:
					for mapping in type_mappings[indicator['type']]:
						indicator_batches[mapping['intel_collection']].append({
							"time": indicator['_time'],
							mapping['intel_field']: indicator['indicator'],
							"threat_key": "otx:%s" % indicator['pulse_id']
						})
						indicator_count_mapped = indicator_count_mapped + 1

			ew.log(ew.INFO, "Found %d indicators, which will result in %d new threat intel entries" % (indicator_count_total, indicator_count_mapped))
			ew.log(ew.INFO, "Beginning push of indicators into threat collections")

			for threat_collection in indicator_batches:
				threat_items = indicator_batches[threat_collection]
				ew.log(ew.INFO, "Pushing %d items into %s (batch size %d)" % (len(threat_items), threat_collection, BATCH_SIZE))
				for small_batch in ([threat_items[i:i+BATCH_SIZE] for i in range(0, len(threat_items), BATCH_SIZE)]):
					body = { "item" : json.dumps(small_batch) }
					resp = service.post('/services/data/threat_intel/item/%s' % (threat_collection), body=urllib.urlencode(body))
					if resp['status'] >= 400:
						ew.log(ew.ERROR, "Error when writing a batch of indicators: %s" % str(resp))

			pulse_query = 'search index=%s earliest=%d _indextime>%d latest=%d sourcetype=otx:pulse | dedup id | eval threat_category=mvjoin(mvdedup(mvappend($industries{}$, $tags{}$, $targeted_countries{}$)), "|") | fillnull value="" adversary description threat_category | fields _time adversary id name description threat_category' % (otx_index, et_safe, et, run_time)

			ew.log(ew.INFO, "Fetching pulses")

			pulse_results = service.jobs.oneshot(pulse_query, count=0)
			pulse_reader = results.ResultsReader(pulse_results)

			threat_group_intel = service.kvstore["threat_group_intel"]

			threat_group_items = []
			for pulse in pulse_reader:
				threat_group_item = {
					"_key" : "otx:%s" % pulse['id'],
					"time" : pulse['_time'],
					"description" : "%s: %s" % (pulse['name'], pulse['description']),
					"source_type" : "otx",
					"source_id" : pulse['id'],
					"source_path" : "https://otx.alienvault.com/pulse/%s" % pulse['id'],
					"source_digest" : pulse['id'],
					"threat_group" : pulse['adversary'],
					"threat_category" : pulse['threat_category'].split("|")
				}
				threat_group_items.append(threat_group_item)

			ew.log(ew.INFO, "Found %d new or updated pulses to load into threat intel collections" % len(threat_group_items))
			ew.log(ew.INFO, "Beginning push of pulses into threat collections")

			for small_batch in ([threat_group_items[i:i+BATCH_SIZE] for i in range(0, len(threat_group_items), BATCH_SIZE)]):
				threat_group_intel.data.batch_save(*small_batch)

			self.save_checkpoint_data(inputs.metadata["checkpoint_dir"], input_name,  { 'last_ran': run_time })

			ew.log(ew.INFO, "Done OTX threat intel management")

	def get_type_mappings(self):
		return {
			"domain": [
				{ "intel_collection": "ip_intel", "intel_field": "domain" },
				{ "intel_collection": "http_intel", "intel_field": "domain" },
				{ "intel_collection": "email_intel", "intel_field": "embedded_domain" },
				{ "intel_collection": "certificate_intel", "intel_field": "domain" }
			],
			"hostname": [
				{ "intel_collection": "ip_intel", "intel_field": "domain" },
				{ "intel_collection": "http_intel", "intel_field": "domain" },
				{ "intel_collection": "email_intel", "intel_field": "embedded_domain" },
				{ "intel_collection": "certificate_intel", "intel_field": "domain" }
			],
			"email": [
				{ "intel_collection": "email_intel", "intel_field": "src_user" }
			],
			"FileHash-MD5": [
				{ "intel_collection": "file_intel", "intel_field": "file_hash" },
				{ "intel_collection": "email_intel", "intel_field": "file_hash" },
				{ "intel_collection": "service_intel", "intel_field": "service_file_hash" },
				{ "intel_collection": "service_intel", "intel_field": "service_dll_file_hash" }
			],
			"FileHash-SHA1": [
				{ "intel_collection": "file_intel", "intel_field": "file_hash" },
				{ "intel_collection": "email_intel", "intel_field": "file_hash" },
				{ "intel_collection": "service_intel", "intel_field": "service_file_hash" },
				{ "intel_collection": "service_intel", "intel_field": "service_dll_file_hash" }
			],
			"FileHash-SHA256": [
				{ "intel_collection": "file_intel", "intel_field": "file_hash" },
				{ "intel_collection": "email_intel", "intel_field": "file_hash" },
				{ "intel_collection": "service_intel", "intel_field": "service_file_hash" },
				{ "intel_collection": "service_intel", "intel_field": "service_dll_file_hash" }
			],
			"FileHash-PEHASH": [
				{ "intel_collection": "file_intel", "intel_field": "file_hash" },
				{ "intel_collection": "email_intel", "intel_field": "file_hash" },
				{ "intel_collection": "service_intel", "intel_field": "service_file_hash" },
				{ "intel_collection": "service_intel", "intel_field": "service_dll_file_hash" }
			],
			"FileHash-IMPHASH": [
				{ "intel_collection": "file_intel", "intel_field": "file_hash" },
				{ "intel_collection": "email_intel", "intel_field": "file_hash" },
				{ "intel_collection": "service_intel", "intel_field": "service_file_hash" },
				{ "intel_collection": "service_intel", "intel_field": "service_dll_file_hash" }
			],
			"URL": [
				{ "intel_collection": "http_intel", "intel_field": "url" }
			],
			"URI": [
				{ "intel_collection": "http_intel", "intel_field": "url" }
			],
			"IPv4": [
				{ "intel_collection": "ip_intel", "intel_field": "ip" },
				{ "intel_collection": "http_intel", "intel_field": "ip" },
				{ "intel_collection": "email_intel", "intel_field": "embedded_ip" },
				{ "intel_collection": "certificate_intel", "intel_field": "ip" }
			],
			"IPv6": [
				{ "intel_collection": "ip_intel", "intel_field": "ip" },
				{ "intel_collection": "http_intel", "intel_field": "ip" },
				{ "intel_collection": "email_intel", "intel_field": "embedded_ip" },
				{ "intel_collection": "certificate_intel", "intel_field": "ip" }
			],
			"CIDR": [
				{ "intel_collection": "ip_intel", "intel_field": "ip" },
				{ "intel_collection": "http_intel", "intel_field": "ip" },
				{ "intel_collection": "email_intel", "intel_field": "embedded_ip" },
				{ "intel_collection": "certificate_intel", "intel_field": "ip" }
			]
		}

	def get_checkpoint_data(self, checkpoint_dir, stanza="(undefined)"):
	    fp = None

	    try:
	        fp = open(self.get_file_path(checkpoint_dir, stanza) )
	        checkpoint_dict = json.load(fp)
	        return checkpoint_dict
	    finally:
	        if fp is not None:
	            fp.close()

	def save_checkpoint_data(self, checkpoint_dir, stanza, data):
	    fp = None

	    try:
	        fp = open(self.get_file_path(checkpoint_dir, stanza), 'w' )
	        json.dump(data, fp)
	    finally:
	        if fp is not None:
	            fp.close()

	def get_file_path(self, checkpoint_dir, stanza):
		return os.path.join( checkpoint_dir, hashlib.sha224(stanza).hexdigest() + ".json" )


if __name__ == "__main__":
	sys.exit(OTXIntelManagerModularInput().run(sys.argv))
