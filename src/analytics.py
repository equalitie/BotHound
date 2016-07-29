"""

AUTHORS: 
Anton Mazhurin

"""

from os.path import dirname, abspath
import os
import sys

import numpy as np
import logging
from datetime import datetime, timedelta
import calendar
import yaml,pdb


#learn2ban classes:
from ip_sieve import IPSieve

from util.es_handler import ESHandler

from bothound_tools import BothoundTools

class Analytics():
	"""

	"""
	def __init__(self, bothound_tools):
		self.bothound_tools = bothound_tools
		self.es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
			bothound_tools.es_host, self.bothound_tools.es_port)

	def calculate_cross_table_banjax(self, incidents):
		# Calculating common Banned Ips for a set of incidents
		es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
				self.bothound_tools.es_host, self.bothound_tools.es_port)
		common = -1
		print "processing..."
		result = []
		groups = []
		for i in incidents:
			incident = self.bothound_tools.get_incident(i)[0]
			#pdb.set_trace()
			banned_ips = es_handler.get_banjax(incident['start'], incident['stop'], incident['target'])
			ips = []
			for p in banned_ips.keys():
				ips.append(p)
			if(common<0):
				common = set(ips)
			else:
				common = common.intersection(ips)

			result.append([len(ips), len(common)])
			groups.append(ips)
			
		for i in range(0, len(groups)):
			print "Incident", i, len(groups[i])

		ip_counts = {}
		for g in groups:
			for ip in g:
				if(ip in ip_counts):
					ip_counts[ip] = ip_counts[ip] + 1
				else:
					ip_counts[ip] = 1

		for i in range(1, len(incidents)+1):
			cur_count = 0
			for ip in ip_counts:
				if(ip_counts[ip] == i):
					cur_count = cur_count + 1
			print cur_count, i

		"""
		#calculate moving intersection
		print "moving intersection"
		for i in range(0, len(incidents)-1):
			ips1 = set(groups[i])
			ips2 = set(groups[i+1])
			print i+1, i+2, len(ips1.intersection(ips2))
		"""

		print "cross table"
		cross_table = []
		for i in range(0, len(incidents)):
			for j in range(i+1, len(incidents)):
			   ips1 = set(groups[i])
			   ips2 = set(groups[j])
			   num = len(ips1.intersection(ips2))
			   cross_table.append((i+1, j+1, len(ips1), len(ips2), num, num * 100.0 / min(len(ips1), len(ips2))))

		sorted_cross_table = sorted(cross_table, key=lambda k: k[5], reverse=True) 
		f1=open('cross_table.txt', 'w+')
		for d in sorted_cross_table:
			s = "{},{},{},{},{},{:.1f}%".format(d[0], d[1], d[2], d[3], d[4], d[5])
			print s
			print >> f1, s
		f1.close()

	def calculate_cross_table(self, incidents):
		common = -1
		result = []
		groups = []
		for i in incidents:
			ips = self.bothound_tools.get_attack_ips([i])
			#ips = self.bothound_tools.get_ips(i)
			if(common<0):
				common = set(ips)
			else:
				common = common.intersection(ips)

			result.append([len(ips), len(common)])
			groups.append(ips)
			
		#for i in range(0, len(groups)):
		#    print "Incident", incidents[i], len(groups[i])

		print "cross table"
		cross_table = []
		for i in range(0, len(incidents)):
			ips1 = set(groups[i])
			for j in range(i+1, len(incidents)):
				ips2 = set(groups[j])
				num = len(ips1.intersection(ips2))
				cross_table.append((incidents[i], incidents[j], len(ips1), len(ips2), num, num * 100.0 / min(len(ips1), len(ips2)) if min(len(ips1), len(ips2)) > 0 else 0))
		sorted_cross_table = sorted(cross_table, key=lambda k: k[5], reverse=True) 
		f1=open('cross_table.txt', 'w+')
		for d in sorted_cross_table:
			s = "{},{},{},{},{},{:.1f}%".format(d[0], d[1], d[2], d[3], d[4], d[5])
			print s
			print >> f1, s
		f1.close()


	def calculate_incident_intersection_plus_ua(self, incidents1, incidents2):
		# Calculating common Banned Ips for two sets of incidents
		es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
				self.bothound_tools.es_host, self.bothound_tools.es_port)
		print "processing..."
		ips1 = []
		for i in incidents1:
			incident = self.bothound_tools.get_incident(i)[0]
			#pdb.set_trace()
			banned_ips = es_handler.get_banjax(incident['start'], incident['stop'], incident['target'])
			for key, value in banned_ips.iteritems():
				ips1.append([key, value])
		
		ips2 = []    
		for i in incidents2:
			incident = self.bothound_tools.get_incident(i)[0]
			#pdb.set_trace()
			banned_ips = es_handler.get_banjax(incident['start'], incident['stop'], incident['target'])
			for key, value in banned_ips.iteritems():
				ips2.append([key, value])

		intersection = 0
		processed_ips = {}
		for ip1 in ips1:
			for ip2 in ips2:
				if ip1[0] == ip2[0]:
					if ip1[0] in processed_ips:
						break
					found = False                        
					for ua1 in ip1[1]['ua'].keys():
						for ua2 in ip2[1]['ua'].keys():
							if(ua1 == ua2):
								found = True
								break
						if found:
							break
					if found:
						intersection = intersection + 1
						processed_ips[ip1[0]] = 1

		num = intersection
		d = [len(ips1), len(ips2), num, num * 100.0 / min(len(ips1), len(ips2))]
		print "group1", incidents1
		print "group2", incidents2
		s = "{},{},{},{:.1f}%".format(d[0], d[1], d[2], d[3])
		print s

	def calculate_unique_ips(self, incidents):
		es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
				self.bothound_tools.es_host, self.bothound_tools.es_port)

		ips = []
		for i in incidents:
			incident = self.bothound_tools.get_incident(i)[0]
			cur_ips = es_handler.get_deflect_unique_ips(incident['start'], incident['stop'], incident['target'])
			ips.append(set(cur_ips.keys()))

		for i in range(0, len(ips)):
			print i, "Num unique IPs:",  len(ips[i])

	def calculate_urls(self, incidents):
		es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
				self.bothound_tools.es_host, self.bothound_tools.es_port)
		incident_urls = []
		for i in incidents:
			incident = self.bothound_tools.get_incident(i)[0]
			urls = es_handler.get_banned_urls(incident['start'], incident['stop'], incident['target'])

			urls_list = []
			for key, value in urls.iteritems():
				temp = [key,value]
				urls_list.append(temp)

			urls_sorted = sorted(urls_list, key=lambda k: k[1], reverse=True) 
			num_most = len(urls_sorted) if len(urls_sorted) < 3 else 3

			incident_urls.append(urls_sorted[0:num_most])

		f1=open('urls.txt', 'w+')
		for urls in incident_urls:
			print "incident", i
			for url in urls:
				print url[1], url[0]
				print >> f1, url[1], url[0]
		f1.close()
			
	def calculate_responses(self, incidents):
		es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
				self.bothound_tools.es_host, self.bothound_tools.es_port)
		res = []
		for i in incidents:
			incident = self.bothound_tools.get_incident(i)[0]
			rates = es_handler.get_banned_responses(incident['start'], incident['stop'], incident['target'])

			res_list = []
			for key, value in rates.iteritems():
				temp = [key,value]
				res_list.append(temp)

			res_sorted = sorted(res_list, key=lambda k: k[1], reverse=True) 
			num_most = len(res_sorted) if len(res_sorted) < 3 else 3

			res.append(res_sorted[0:num_most])

		i = 1
		for incident in res:
			print "incident", i
			i = i + 1
			for r in incident:
				print r[1], r[0]

	def calculate_user_agents(self, incidents):
		es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
				self.bothound_tools.es_host, self.bothound_tools.es_port)
		res = []
		for i in incidents:
			incident = self.bothound_tools.get_incident(i)[0]
			res_dict = es_handler.get_banned_user_agents(incident['start'], incident['stop'], incident['target'])

			res_list = []
			for key, value in res_dict.iteritems():
				temp = [key,value]
				res_list.append(temp)

			res_sorted = sorted(res_list, key=lambda k: k[1], reverse=True) 
			num_most = len(res_sorted) if len(res_sorted) < 50 else 50
			print "incident", i, "winner", res_sorted[0]
			res.append(res_sorted[0:num_most])

		i = 1
		f1=open('user_agents.txt', 'w+')
		for incident in res:
			print >>f1, "incident", i
			print "incident", i
			i = i + 1
			for r in incident:
				print >> f1, r[0], r[1] 
				print r[0], r[1] 
		f1.close()

	def get_banned_ips(self, incidents):

		es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
				self.bothound_tools.es_host, self.bothound_tools.es_port)
		index = 1
		for i in incidents:
			incident = self.bothound_tools.get_incident(i)[0]
			ips = es_handler.get_banjax(incident['start'], incident['stop'], incident['target'])

			f1=open('incident_{}({}).txt'.format(index, i), 'w+')
			for ip in ips:
				#pdb.set_trace()
				print >> f1, ip
			f1.close()
			index = index + 1

	def calculate_banned_devices(self, incidents):
		es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
				self.bothound_tools.es_host, self.bothound_tools.es_port)
		res = []
		for i in incidents:
			incident = self.bothound_tools.get_incident(i)[0]
			res_dict = es_handler.get_banned_devices(incident['start'], incident['stop'], incident['target'])

			devices = {}
			for key, value in res_dict.iteritems():
				if value in devices:
					devices[value] = devices[value] + 1 
				else:
					devices[value] = 1 

			res_list = []
			for key, value in devices.iteritems():
				temp = [key,value]
				res_list.append(temp)

			res_sorted = sorted(res_list, key=lambda k: k[1], reverse=True) 
			num_most = len(res_sorted) if len(res_sorted) < 40 else 40
			if len(res_sorted) > 0:
				print "incident", i, "winner", res_sorted[0]
			res.append(res_sorted[0:num_most])

		i = 1
		f1=open('devices.txt', 'w+')
		for incident in res:
			print >>f1, "incident", i
			print "incident", i
			i = i + 1
			for r in incident:
				print >> f1, r[0], r[1] 
				print r[0], r[1] 
		f1.close()
	
	def calculate_pingback_domains(self, incidents):
		es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
				self.bothound_tools.es_host, self.bothound_tools.es_port)

		index = 1
		for i in incidents:
			incident = self.bothound_tools.get_incident(i)[0]
			res_dict = es_handler.get_pingback_domains(incident['start'], incident['stop'], incident['target'])

			res_list = []
			for key, value in res_dict.iteritems():
				temp = [key,value]
				res_list.append(temp)

			res_sorted = sorted(res_list, key=lambda k: k[1], reverse=True) 
			f1=open('pingback_domains_incident_{}({}).txt'.format(index,i), 'w+')
			for r in res_sorted:
				print >> f1, r[0] 
			f1.close()
			index = index + 1

	def find_intersections(self, id_incidents, 
		date_from, 
		date_to, 
		file_name = "intersection_report.txt",
		title = "",
		target_domain_no_www = None, #domain without "www."
		window_size_in_hours = 24,
		threshold_in_percentage = 10.0) :

		es_handler = ESHandler(self.bothound_tools.es_user, self.bothound_tools.es_password,
				self.bothound_tools.es_host, self.bothound_tools.es_port)
		ips = []
		start = date_from
		f1=open(file_name, 'w+')
		print >>f1, "Intersection Report:", title
		print >>f1, "\nIncidents:"
		for id_incident in id_incidents:
			incident = self.bothound_tools.get_incident(id_incident)[0]
			ips = ips + es_handler.get_banjax(incident['start'], incident['stop'], incident['target']).keys()
			print >>f1, "Incident {}, target domain = {}, Start:{}, Stop:{}".format(
				id_incident, incident['target'], incident['start'], incident['stop'])

		ips = set(ips)
		print >>f1, "\nNotal number of banned IPs:", len(ips)

		print >>f1, "\nFinding intersection with data from {} to {}".format(date_from, date_to)
		print >>f1, "Threshold = {}%".format(threshold_in_percentage)
		print >>f1, "Target domain = {}".format(target_domain_no_www if target_domain_no_www != None else "all domains")
		print >>f1, "Sliding window size : {} hours".format(window_size_in_hours)
		print >>f1, "\nIntersections found:"

		while start < date_to:
			stop = start + timedelta(hours=window_size_in_hours)
			print "processing {}, + {} hours...".format(start, window_size_in_hours)

			ips_to_check = es_handler.get_banjax(start, stop, target_domain_no_www).keys()
			ips_to_check = set(ips_to_check)
			intersection = len(ips.intersection(ips_to_check))
			percentage1 = intersection * 100.0 / len(ips)
			percentage2 = intersection * 100.0 / len(ips_to_check)

			if percentage1 > threshold_in_percentage or percentage2 > threshold_in_percentage:
				print >> f1, "Original:{:.2f}%, Window:{:.2f}%, Total: {}, start : {} + {} hours".format(
					percentage1, percentage2, intersection, start, window_size_in_hours)

			start = start + timedelta(hours=window_size_in_hours/2.0)

		print >>f1, "End"
		f1.close()

	def calculate_intersection_with_file(self, id_incidents, input_file_name, file_name):
		lines = []
		with open(input_file_name) as f:
			lines = f.read().splitlines()  

		ips_to_check = []
		for line in lines:
			splitted_line = line.split('|')
			if(len(splitted_line) < 2):
				continue
			ip = splitted_line[len(splitted_line)-2]
			
			#splitted_line = line.split(',')
			#if(len(splitted_line) < 3):
			#	continue
			#ip = splitted_line[1].strip()

			#pdb.set_trace()
			ips_to_check.append(ip)
		ips_to_check = set(ips_to_check)

		ips = []
		f1=open(file_name, 'w+')
		print >>f1, "Intersection Report"
		print >>f1, "\nFinding intersection with data from file : {}".format(input_file_name)
		print >>f1, "\nNotal number of file IPs:", len(ips_to_check)

		attacks = self.bothound_tools.get_attack_ids(id_incidents)
		for attack in attacks:
			print >>f1, "\n__________ Botnet {}:".format(attack)
			ips = self.bothound_tools.get_attack_ips_decrypted(id_incidents, attack)
			#pdb.set_trace()
			ips = set(ips)
			print >>f1, "Total IPs:", len(ips)
			intersection = len(ips.intersection(ips_to_check))
			if(intersection > 0):
				percentage1 = intersection * 100.0 / len(ips)
				percentage2 = intersection * 100.0 / len(ips_to_check)
				print >> f1, "# identical IPs: {}".format(intersection)
				print >> f1, "% of botnet IPs: {:.2f}%".format(percentage1)
				print >> f1, "% of file's IPs: {:.2f}%".format(percentage2)

		f1.close()

	def get_unique_lines(self, file_name_input, file_name_output):
		lines = []
		with open(file_name_input) as f:
			lines = f.read().splitlines()  

		lines = set(lines)

		f1=open(file_name_output, 'w+')
		for l in lines:
			print >> f1, l
		f1.close()
		return len(lines)


if __name__ == "__main__":

	stram = open("../conf/bothound.yaml", "r")
	conf = yaml.load(stram)

	bothound_tools = BothoundTools(conf)
	bothound_tools.connect_to_db()


	analytics = Analytics(bothound_tools)
	
	#print analytics.get_unique_lines("botnets/ips_botnet_1.txt", "botnets1/ips_botnet_1.txt")
	#print analytics.get_unique_lines("botnets/ips_botnet_2.txt", "botnets1/ips_botnet_2.txt")
	#print analytics.get_unique_lines("botnets/ips_botnet_4.txt", "botnets1/ips_botnet_4.txt")
	#print analytics.get_unique_lines("botnets/ips_botnet_5.txt", "botnets1/ips_botnet_5.txt")
	#print analytics.get_unique_lines("botnets/ips_botnet_6.txt", "botnets1/ips_botnet_6.txt")
	#print analytics.get_unique_lines("botnets/ips_botnet_7.txt", "botnets1/ips_botnet_7.txt")


	#id_incidents = [24,25,26,19,27]
	#id_incidents = [29,30,31,32,33,34]
	id_incidents = [50,51,52,53,54]

	#bothound_tools.calculate_attack_metrics(id_incidents)

	#id_incident, id_attack, cluster_indexes1, cluster_indexes2, id_incidents, features = []

	#bothound_tools.calculate_distances(id_incident = 29, id_attack = 1, cluster_indexes1 = [], cluster_indexes2 = [], 
	#	id_incidents = [29,30,31,32,33,34,36,37,39,40,42], features = [])

	bothound_tools.calculate_common_ips([50], 8, [50,51,52,53,54])

	#bothound_tools.incidents_summary(id_incidents)

	#attacks = bothound_tools.get_attacks(id_incidents) # show attack count
	#for a in attacks:
	#	print a

	#bothound_tools.get_top_attack_countries(id_incidents)

	#print id_incidents
	#bothound_tools.extract_attack_ips(id_incidents)

	#analytics.calculate_intersection_with_file(id_incidents, 
	#	"./botnet_xmlrpc_20160414.csv", "intersection_botnet_xmlrpc_20160414.txt")
	
	#for i in range(1, 9):
	#    bothound_tools.extract_attack_ips(id_incidents, i)

	#analytics.calculate_cross_table(id_incidents)

	#analytics.calculate_unique_ips(id_incidents)

	#urls = analytics.calculate_urls(id_incidents)

	#analytics.calculate_responses(id_incidents)

	#analytics.get_banned_ips(id_incidents)

	#analytics.calculate_user_agents(id_incidents)

	#analytics.calculate_banned_devices(id_incidents)

	#analytics.calculate_pingback_domains(id_incidents)

	#analytics.calculate_intersection_with_file([29,30,31,32,33,34], "./btselem/btselem_wordpress_ips.deny", "./btselem/bds_vs_btselem_wordpress_ips.txt")
	#analytics.calculate_intersection_with_file([29,30,31,32,33,34], "./btselem/btselem_stupid.deny", "./btselem/bds_vs_btselem_stupid.txt")
	#analytics.calculate_intersection_with_file([29,30,31,32,33,34], "./btselem/btselem_wp_20150515-00_ips.deny", "./btselem/bds_vs_btselem_wp_20150515-00_ips.txt")

	#analytics.calculate_intersection_with_file([35,36,37], "./btselem/btselem_wordpress_ips.deny", "./btselem/btselem_vs_btselem_wordpress_ips.txt")
	#analytics.calculate_intersection_with_file([35,36,37], "./btselem/btselem_stupid.deny", "./btselem/btselem_vs_btselem_stupid.txt")
	#analytics.calculate_intersection_with_file([35,36,37], "./btselem/btselem_wp_20150515-00_ips.deny", "./btselem/btselem_vs_btselem_wp_20150515-00_ips.txt")


	"""
	# test for find_intersections
	analytics.find_intersections([33], date_from = datetime(2016,03,01),date_to = datetime(2016,03,03),
		file_name = "intersection_bdsmovement.txt",title = "Bdsmovement.org", window_size_in_hours = 4)
	"""

	# bdsmovement intersections
	"""
	analytics.find_intersections([29,30,31,32,33,34], 
	   date_from = datetime(2015,1,1), date_to = datetime(2016,2,1),
	   file_name = "intersection_bdsmovement.txt",
	   title = "Bdsmovement.org",  window_size_in_hours = 24, threshold_in_percentage = 3)
	"""
  

	# kotsubynske intersections
	"""
	analytics.find_intersections([24,25,26,19,27], 
		date_from = datetime(2015,1,1), date_to = datetime(2016,2,1),
		file_name = "intersection_kotsubynske.txt",
		title = "Kotsubynske.org",  window_size_in_hours = 24, threshold_in_percentage = 3)
	"""


	"""
	sql for counting botnets

		select distinctrow attack from sessions
		where (id_incident = 29 or id_incident = 30 or  id_incident = 31 or id_incident = 32 or id_incident = 33 or id_incident = 34)

	select count(distinctrow IP) from sessions
	where (id_incident = 29 or id_incident = 30 or  id_incident = 31 or id_incident = 32 or
	id_incident = 33 or id_incident = 34 or id_incident = 42)
	and attack = 2


	select distinctrow id_incident from sessions
	where (id_incident = 29 or id_incident = 30 or  id_incident = 31 or id_incident = 32 or id_incident = 33 or id_incident = 34)
	and attack = 1

	UPDATE sessions
	SET attack=7
	WHERE id_incident = 34 and attack = 1

	select ua from session_user_agent, sessions, user_agents
	where sessions.id_incident = 41 and session_user_agent.id_session = sessions.id
	and user_agents.id = id_user_agent
	limit 10

	select count(distinctrow IP), id_country from sessions
	where id_incident in (29,30,42,31,32,33,34) and attack =1 and id_country = 11 

	"""	

