"""
Analyse efficacy of learn2ban SVM system

AUTHORS:

- Bill (bill@equalit.ie) 2013/02/09
- Vmon: July 2013: Change log status. Trying to return back to OOP model
		after learn2bantool reconstruction disaster
- Vmon: Nov 2013: store the experiment model along with the experminet
				  results

- Vmon: Jan 2016: Adopt the code to bothound
"""

from multiprocessing import Process
from os.path import dirname, abspath
import os
import sys
import yaml,pdb
import time

try:
	src_dir = dirname(dirname(abspath(__file__)))
except NameError:
	#the best we can do to hope that we are in the test dir
	src_dir = dirname(getcwd())

sys.path.append(src_dir)

import numpy as np
import logging
from datetime import datetime, timedelta
import calendar

#learn2ban classes:
from ip_sieve import IPSieve

#feature classes
from features.src.learn2ban_feature import Learn2BanFeature
from features.src.feature_average_request_interval import FeatureAverageRequestInterval
from features.src.feature_cycling_user_agent import FeatureCyclingUserAgent
from features.src.feature_html_to_image_ratio import FeatureHtmlToImageRatio
from features.src.feature_HTTP_response_code_rate import FeatureHTTPResponseCodeRate
from features.src.feature_geo import FeatureGEO
from features.src.feature_payload_size_average import FeaturePayloadSizeAverage
from features.src.feature_percentage_consecutive_requests import FeaturePercentageConsecutiveRequests
from features.src.feature_request_depth import FeatureRequestDepth
from features.src.feature_request_depth_std import FeatureRequestDepthStd
from features.src.feature_session_length import FeatureSessionLength
from features.src.feature_user_agent import FeatureUserAgent
from features.src.feature_variance_request_interval import FeatureVarianceRequestInterval

#train to ban and other tools
from training_set import TrainingSet

from util.es_handler import ESHandler
from bothound_tools import BothoundTools
from threading import Thread

nb_training = 10
training_portions = [x / float(nb_training) for x in range(1, nb_training)]

class SessionComputer(Thread):
	"""
	This class read the db for the time of the attack from the database
	and compute the sessions for the chosen incidents
	"""
	def __init__(self, bothound_tools):
		"""
		store the exp config in self's attribute.
		"""
		Thread.__init__(self)
		self.daemon = True
		utc_datetime = datetime.utcnow()
		self.bothound_tools = bothound_tools
		self.es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
			bothound_tools.es_host, self.bothound_tools.es_port)

	def process_incident(self, incident):
		"""
		get the incident time from the db and gathers all features

		INPUT:
			log_files: the logs that we went through it.
		"""
		if(incident is None):
			return 

		ip_sieve = IPSieve()
		ip_records = {}		
		banned_ips = []

		if(incident["file_name"] is None) or (len(incident["file_name"]) == 0):
			# get the logs from ES
			# get the logs from ES
			banned_ips = self.es_handler.get_banjax(incident['start'], incident['stop'], incident['target'])
			ats_records = self.es_handler.get(incident['start'], incident['stop'], incident['target'])

			# calculate IP dictionary with ATS records
			ip_records = ip_sieve.process_ats_records(ats_records)
		else:
			# read the sessions from the log file
			ip_sieve.add_log_file(incident["file_name"])
			ip_records = ip_sieve.parse_log("nginx")
	
		# calculate features
		ip_feature_db = {}

		#At this stage it is only a peliminary list we might lose features
		#due to 0 variance
		self._active_feature_list = []
		#do a dry run on all features just to gather the indeces of all available
		#features
		for CurentFeature in Learn2BanFeature.__subclasses__():
			f = CurentFeature(ip_records, ip_feature_db)
			self._active_feature_list.append(f._FEATURE_INDEX)

		for CurentFeature in Learn2BanFeature.__subclasses__():
			f = CurentFeature(ip_records, ip_feature_db)
			#logging.info("Computing feature %i..."% f._FEATURE_INDEX)
			print "Computing feature %i..."% f._FEATURE_INDEX
			f.compute()

		# post process the features
		ip_feature_db = self.bothound_tools.post_process(ip_feature_db)

		# delete the old sessions for thie incidend
		self.bothound_tools.delete_sessions(incident['id'])

		#print ip_feature_db
		self.bothound_tools.add_sessions(incident['id'], ip_feature_db, banned_ips)
		self.bothound_tools.set_incident_process(incident['id'], False)
		print "Incident {} processed.".format(incident['id'])
		return ip_feature_db

	def compute_incidents(self):
		"""
		check all incidents which needs to be processed and compute the features on them
		finally store the sessions in the db
		"""
		#this make more sense to happens in the constructor however,
		for incident in self.bothound_tools.get_incidents(process = True):
			cur_session_feature_db = self.process_incident(incident)
		

	def store_results(self, session_feature_db):
		# Add the result to the database
		for cur_sesion in session_feature_db:
			db_tools.store(cur_session)

	def run(self):
		print "Running SessionComputer..."
		while True:
			self.compute_incidents()
			time.sleep(10)

		print "Exit session computer."


if __name__ == "__main__":

	stram = open("../conf/bothound.yaml", "r")
	conf = yaml.load(stram)

	bothound_tools = BothoundTools(conf)
	bothound_tools.connect_to_db()

	session_computer = SessionComputer(bothound_tools)
	session_computer.start()

	while True:
		pass
