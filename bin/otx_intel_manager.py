import sys
import time
from collections import defaultdict

from modular_input import ModularInput, DurationField, IntegerField, Field

import splunklib.client as client
import splunklib.results as results

class OTXIntelManagerModularInput(ModularInput):

	def __init__(self):

		scheme_args = {'title': "Open Threat Exchange Intel Manager",
					   'description': "Integrate OTX pulses into the Splunk ES Threat Intelligence framework",
					   'use_external_validation': "true",
					   'streaming_mode': "xml",
					   'use_single_instance': "true"}

		args = [
				Field("otx_index", "OTX index", "The index in which we will find the OTX events", empty_allowed=False),
				IntegerField("backfill_days", "Backfill days", "The number of days to backfill indicators for on first run", empty_allowed=False),
				DurationField("interval", "Interval", "The interval defining how often to check for new indicators; can include time units (e.g. 15m for 15 minutes, 8h for 8 hours)", empty_allowed=False)
		]

		ModularInput.__init__( self, scheme_args, args, logger_name='otx_intel_manager' )

	def run(self, stanza, cleaned_params, input_config):

		interval = cleaned_params["interval"]
		backfill_days = cleaned_params["backfill_days"]
		index = cleaned_params.get("otx_index", "otx")
		source = stanza

        	run_time = time.time()

		type_mappings = {
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
			]
		}

		if self.needs_another_run(input_config.checkpoint_dir, stanza, interval):

			try:
				checkpoint_data = self.get_checkpoint_data(input_config.checkpoint_dir, stanza, throw_errors=True)
			except IOError:
				checkpoint_data = None
			except ValueError:
				self.logger.exception("Exception generated when attempting to load the checkpoint data")
				checkpoint_data = None

			# Try to load the last ran date from the checkpoint data
			if checkpoint_data is not None and 'last_ran' in checkpoint_data:
				last_ran = checkpoint_data['last_ran']
			else:
				last_ran = None

		 	if last_ran is not None:
		 		et = str(last_ran)
		 	else:
		 		et = "-%dd" % backfill_days

			service = client.Service(token=input_config.session_key, owner="nobody")

			indicator_query = "search index=%s earliest=%s latest=%d sourcetype=otx:indicator | fields _time type indicator pulse_id" % (index, et, run_time)

			indicator_results = service.jobs.oneshot(indicator_query, count=0)
			indicator_reader = results.ResultsReader(indicator_results)

			indicator_batches = defaultdict(list)

			for indicator in indicator_reader:
				if indicator['type'] in type_mappings:
					for mapping in type_mappings[indicator['type']]:
						indicator_batches[mapping['intel_collection']].append('{ "time": "%s", "%s": "%s", "threat_key": "otx:%s" }' % (indicator['_time'], mapping['intel_field'], indicator['indicator'], indicator['pulse_id']))

			for threat_collection in indicator_batches:
				threat_items = indicator_batches[threat_collection]
				for small_batch in ([threat_items[i:i+20] for i in range(0, len(threat_items), 20)]):
					service.post('/services/data/threat_intel/item/%s' % (threat_collection), body='item=[%s]' % (','.join(small_batch)))

			pulse_query = 'search index=%s earliest=%s latest=%d sourcetype=otx:pulse | eval threat_category=mvjoin($tags{}$, "|") | fillnull value="" adversary description threat_category | fields _time adversary id name description threat_category' % (index, et, run_time)
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
			for small_batch in ([threat_group_items[i:i+20] for i in range(0, len(threat_group_items), 20)]):
				threat_group_intel.data.batch_save(*small_batch)

			self.save_checkpoint_data(input_config.checkpoint_dir, stanza,  { 'last_ran': run_time })


if __name__ == '__main__':
	try:
		otx_intel_manager_input = OTXIntelManagerModularInput()
		otx_intel_manager_input.execute()
		sys.exit(0)
	except Exception as exception:

		# This logs general exceptions that would have been unhandled otherwise (such as coding errors)
		if otx_intel_manager_input is not None:
			otx_intel_manager_input.logger.exception("Unhandled exception was caught, this may be due to a defect in the script")

		raise exception
