BotHound
=======

Automatic DDoS attack detector and botnet classifier
-----------

# Description
Bothound is an automatic DDoS attack detector and botnet classifier. Its purpose is to create a historical classification of the attacks with detailed information regarding the attackers (country-based, time-based, etc.).

Bothound's role is to detect and classify the attacks (incidents), using the anomaly-detection and machine-learning tool [Grey Memory](https://github.com/greymemory). BotHound attack classifier reacts to anomalous detectors and starts gathering live information from the Deflect network. It computes a behaviour vector for all visitors of the network when Grey Memory detects an anomaly. BotHound groups the client IPs in different groups (clusters) using unsupervised machine learning algorithms in order to profile the group of malicious visitors. It uses different measures to tag the groups which are more likely to be attackers. After that, it feeds all the behaviour vectors of bot IPs into a classifier to detect if the botnet has a history of attacking the [Deflect network](https://wiki.deflect.ca/wiki/Main_Page) in the past. It finally generates a report based on its conclusions for Deflect's sysops and gets feedback to improve its classification performance.

# Installation

## Python
Python 2.7 should be installed

## Libraries

First add the Jessie backports repository to `/etc/apt/sources.list`:

    deb http://http.debian.net/debian jessie-backports main

and run `apt-get update`.

The following libraries should be installed:  

```  
[sudo] apt-get install emacs python libmysqlclient-dev build-essential python-dev python-numpy python-setuptools python-scipy libatlas-dev python-matplotlib python-mysqldb python-geoip libffi-dev python-dnspython libssl-dev python-zmq   
[sudo] apt-get install python-pip
[sudo] pip install -U scikit-learn  
[sudo] apt-get install python-twisted
[sudo] apt-get install git  
[sudo] apt-get install openjdk-8-jre openjdk-8-jdk
[sudo] apt-get install mysql-server
[sudo] apt-get install ant
 ```  
When installing `openjdk-8-jre` and `openjdk-8-jdk`, make sure that version 7 is not installed.
 
 
## Adminer
Install [Adminer](https://www.adminer.org/) interface  

## Jupyter
* First make sure that you install Jupyter locally because nbextension has a bug and is only able to install if there is a local installation.  
``` 
sudo pip install jupyter_contrib_core
sudo pip install jupyter --user
```

* Install Jupyter system-wide  
```
sudo pip install jupyter
```

* Install Jupyter nbextensions  
```
pip install https://github.com/ipython-contrib/IPython-notebook-extensions/archive/master.zip
```

* The file is erroneously copied in the local folder. Copy the files to the system-wide folder.  
```
sudo cp -R /root/.local/share/jupyter /usr/local/share/
sudo chmod -R a+r /usr/local/share/jupyter 
```

## Get Source Code 
```
git clone https://github.com/equalitie/bothound  
cd bothound/
```

## Install Packages
Install required packages from requirements.txt:  

```
pip install -r requirements.txt  
```

## Configuration 
You need to create a configuration file bothound.yaml

* Make a copy of the [example configuration file](conf/rename_me_to_bothound.yaml)  
* Rename the copy to bothound.yaml  
* Update the file with your credentials.  

bothound.yaml description:  

* encryption\_passphrase - the password for IP encryption  
* hash\_passphrase - the solt for hash function used for IP hash, stored in the database  
* sniffles section - not supported yet  
* elastic\_db - Elastic search node credentials  
	
## Greymemory installation
* Build greymemory using the following script:  
```
sh build_greymemory.sh
```  

The script will get the source code from github and build the source code using ant.
Make sure the build is successfull and subfolder "greymemory/greymemory.AnomalyDetector/dist" contains greymemory.AnomalyDetector.jar.
* rename greymemory/greymemory.AnomalyDetector/rename\_me\_to\_AnomalyDetector.config to AnomalyDetector.config  

## Greymemory configuration
Greymemory monitors the rate of successful http requests for every protected host.
To calculate this rate Greymemory sends two request to ElasticSearch: 1) to get the total number of successful http request, and 2) to get the total number of failed http requests. The rate is calculated every 2 minutes by default. Every time the new rate is calculated Greymemory calculates the corresponding anomaly rate for the new value. If this anomaly rate is greater than a threshold, an anomaly is reported to bothound. Bothound creates a new incident for the corresponding host.

File greymemory/greymemory.AnomalyDetector/AnomalyDetector.config contains greymemory configuration:  

* threshold - the threshold value of anomaly rate(default is 0.95)  
* sample\_rate\_in\_minutes - the sampling rate (default is 2 minutes)  
* es\_host, es\_port, es\_user, es\_password - Elastic Search credentials  
* mail\_alert1, mail\_alert2,... - emails for anomaly notifications  
* target\_host1, target\_host2=... - the hosts being monitored. Don't use "www."   

# Initialization

## Creating a database
* Make sure Mysql server is up and running.  
* To create a database, you just need to launch bothound :  
```
python src/bothound.py  
```
Make sure the database and the tables are created successfully.  
* Create a test incident using the followin sql :  
```
INSERT INTO incidents (start,stop,process,target) VALUES (2016-06-01, 2016-06-02, 1, 'mysite.com');
```
* Make sure bothound is processing data from elastic search server. You should see the following message if the testing incident is processed correctly : "Incident 1 processed"

## Establish ZMQ relay
ZMQ relay script provides communication channel between Greymemory and Bothound. Bothound uses TCP socket to connect to the relay. The relay uses encrypted ZMQ messages to communicate to Bothound. This design enables to scale the system and run multiple instances of Greymemory.
To run the relay:  
```
python src/util/socket2zmq.py
```  
Make sure you see the message "Listening on port ... , relayint to ZMQ port ..."

## Test Greymemory
To run greymemory :  
```
cd ./greymemory/greymemory.AnomalyDetector
sh anomaly_detector.sh
```  
Make sure you see a test anomaly message in bothound console : "New incident : test_host, ..."

# Running

## Running Bothound
The following scripts are created to simply the launch procedure. Launch in any order:  

* bothound.sh  
* greymemory.sh  
* relay.sh  

## Running Jupyter
1. Make sure the Jupyter instance is running on the Bothound server. 
To run the instance, launch this command:  
```
jupyter notebook --no-browser --port=8889
```
2. Establish a tunnel to the Jupyter instance from your local computer:  
```
ssh -N -L 8889:127.0.0.1:8889 user@server
```
3. Open the local URL [http://localhost:8889/](http://localhost:8889/).
Make sure you see a list of files and folders.

# Definitions
* Session - an IP and a vector of feature values recorded and calculated during a period of the IP activity  
* Feature - an individual measurable property of a session   
* Incident - a set of sessions recorded during a time interval  
* Attack - a subset of sessions in an incident which was labeled as an attack  
* Botnet - a list of IPs that participated in similar attacks   

# Incidents 
Incidents are created manually using the Adminer interface. In the future, incidents will be created automatically based on messages from the Grey Memory anomaly detector.

## Creating incidents 
* Insert a new record into the "incidents" table. 
* Make sure you filled at least the "start", "stop" and "target" fields.
* The target URL should not contain "www." at the beginning. If you have multiple targets, you can add them separated by a comma.
* Set "process" field to 1.

## Creating incidents from nginx logs
* Insert a new record into the "incidents" table. 
* Make sure you filled "file_name" with the full path to a nginx log file.
* Set "process" field to 1.

## Jupyter Notebook
The [Jupyter Notebook](http://jupyter.org/) is a web application that allows you to create and share documents that contain live code, equations, visualizations and explanatory text. 
Notebook contains a list of cells (markdown, python code, graphs). 
Use Shift+Enter to execute a cell.
You can fold/unfold the content of a cell using the left "arrow" key.

# Sessions

Bothound calculates sessions for all the records in the incidents table containing "1" in the "Process" field. 
* Bothound monitors records in INCIDETNS table. 
* Bothound recalculates sessions for all the records from "Incident" table containing "1" in the "Process" field. 
* For regular incidents, the Bothound runs ElasticSearch queries. For nginx incidents, the Bothound will parse the corresponding log file.
* The sessions will be stored in the "sessions" table.

## IP Encryption
For security reasons, Bothound stores only encrypted IPs in the session table, in the "ip\_encrypted", "ip\_iv",and "ip\_tag" fields. 
The hash of the IP is also stored in the "ip" field.
The encryption key is set in the configuration file "conf/bothound.yaml" ("encryption\_passphrase").
Bothound supports multiple encryption keys. The encryption table contains the hash value of the key which was used to encrypt the IPs of an incident. 

In order to get the decrypted IPs of the incident, use the extract_attack_ips() function in bothound_tools.py 

# Attacks
Bothound uses clustering methods in order to separate attackers from regular traffic.
This process of labelling a subset of incident sessions as an attack is manual. 
The user opens a Jupyter notebook, chooses an incident, clusters the sessions with different clustering algorithms and manually assigns an arbitrary attack number to the selected clusters. 

## Loading incident
* Open Jupyter interface URL: [http://localhost:8889/](http://localhost:8889/)
* Open src/Clustering.ipynb  
* Execute "Initialization" chapter  
* "Configuration" chapter: change the assignment of variable "id\_incident = ..." to your incident number  
* "Configuration" chapter: uncomment the features you want to use: "features = [...]"  
* Execute "Configuration" chapter  
* Execute "Load Data" chapter 

## Clustering
* Execute DBSCAN Clustering chapter. 
After the clustering is done, you will see a bar plot of clusters. 
Y-axis corresponds to the size of the cluster. Every cluster has its own color from a predefined palette.

* Use plot3() function in the second cell of the chapter to create different 3D scatter plots of the calculated clusters:

```python
plot3([0,1,3], X, clusters, [])  
```
The first argument of this function is an array of indexes of the 3 features to display at the scatter plot. Note that these are the indexes in the array of uncommented features from the "Configuration" chapter. If you have more than 3 uncommented features, choose different indexes and re-execute plot3() cell.

* Choose your features carefully. 
It is always better to experiment and play with different features subsets (uncommented in "Configuration" chapter). Clustering is very sensitive to feature selection. 
Different attacks might have different distinguishable features. 
If you change your features selection in "Configuration" chapter, you must re-execute the "Configuration", "Load Data", and "Clustering" chapters. 

* Double clustering.
In some cases DBSCAN clustering is not good enough. The suspected cluster might have a weird shape and even contain two different botnets. In order to further divide such a cluster, you can use the second iteration, which we call "Double Clustering". You should choose the target cluster after the first clustering, as well as the number of clusters for K-Means clustering algorithm.  
The second cell in this chapter is the same plot3() function which displays a 3D scatter plot of double clustering.

```python
plot3([0,1,3], X2, clusters2, [])
```
Note that you should use X2 and clusters2 arguments.

## Attack saving
* Choose your attack ID(s).
Attack IDs are arbitrary numbers you assign to each botnet. The attack is identified by its incident ID and attack ID.
It is possible to have more than one attack in a single incident. 

* Modify the tools.label\_attack() function arguments  
If you have more than one attack number to save, you should add a call to the label/attack() function for every attack.  
For example, for attack #1 you choose cluster #3:  
```python 
tools.label_attack(id_incident, attack_number = 1, selected_clusters = [3], selected_clusters2 = [])  
```
If you use double clustering, don't forget to specify the indexes for selected_clusters2.
For example, for attack #1 you will choose cluster #3 and double clusters #4 and #5:   
```python
tools.label_attack(id_incident, attack_number = 1, selected_clusters = [3], selected_clusters2 = [4,5])  
```

* Execute "Save Attack" chapter. 

## Feature exploration
In this section, users can explore the distribution of a single feature over the clusters to verify the quality of the clustering results.  

```python
box_plot_feature(clusters, num_clusters = 4, X = X, feature_index = 2)  
```

The function will display a boxplot of feature values distribution per cluster.
Using this graph, you can get more insight into the quality of the clustering you used.  
For instance, if you know in advance that the attack you are clustering should have a significant higher hit rate, then you can expect that a proper attack cluster should have a similar high boxplot of "request_interval" features.

## Common IPs with other incidents
If two attacks share a significant portion of identical IPs, they are likely to belong to the same botnet.

```python
plot_intersection(clusters, num_clusters, id_incident, ips, id_incident2 = ..., attack2 = -1)  
```

This function will create a bar plot highlighting portions of the clusters which share identical IPs with another incident (specified by variable id_incident2). It is also possible to specify a particular attack index.

## Countries
This graph explores the country distribution over the clusters. 

## Banjax
Even if an IP was banned during the incident, Bothound does not use this information for clustering.
Nevertheless, the distribution of banned IPs over the clusters might be useful.
This graph will display portions of IPs, banned by [Banjax](https://github.com/equalitie/banjax) per cluster.

# Analytics
When attack labeling is completed (see "Attacks" chapter), a set of analytic scripts may be executed from a separate Jupyter notebook:

* Open Jupyter interface URL: [http://localhost:8889/](http://localhost:8889/)
* Open src/Analytics_1.ipynb 
* Execute "Initialization" chapter  
* "Configuration" chapter: type the incident IDs to explore  
* Execute "Read Data" chapter

## Attacks Summary
In this section you can get the general information about the attacks in the selected incidents:  
* number of unique IPs  
* IDs of labeled attacks  
* number of bots in each attack  
```python
Incident 29, num IPs = 14790, num Bots = 13013  
Incident 42, num IPs = 10963, num Bots = 9023  
Attack 1 = 13857 ips  
Attack 4 = 2589 ips  
Attack 7 = 11746 ips  
```

## Countries by attack
A barplot of country distribution over the botnets.

## Countries by Incident
A barplot of country distribution over the incidents.

## User Agents
The top used User Agent string used by attackers.

## Attacks Scatter Plot
This 3D scatter plot illustrates the distribution of attack sessions vs. the regular traffic.
The first cell contains the code for preprocessing the plot.
The first line in this cell defines an array with all the features.  
```python
features = [  
    "request_interval", #1  
    "ua_change_rate",#2  
    "html2image_ratio",#3  
    "variance_request_interval",#4  
    "payload_average",#5  
    "error_rate",#6  
    "request_depth",#7  
    "request_depth_std",#8  
    "session_length",#9  
    "percentage_cons_requests",#10  
]  
...  
```  
The second cell contains the call to plot3() function (the same function used in "Clustering.ipynb" Jupyter notebook).
Make sure you correctly specify the first argument: an array of 3 indexes from the features array.  
```python
plot3([3,2,5], X, incident_indexes, -1, "Attack ")  
```  

## Attack metrics
The basic 3 metrics of the attacks:  

* session length   
* html/image ratio  
* hit rate  

## Attack similarity
Attack similarity is a very important measure. It gives you a quantitative measure of how close a selected attack is to previously processed attacks.  
```python
tools.calculate_distances(  
    id_incident = 29, # incident to explore  
    id_attack = 1, # attack to explore  
    id_incidents = [29,30,31,32,33,34,36,37,39,40,42], # incidents to compare with  
    features = [] # specify the features by name. Use all features if empty  
)  
```  
The output is a list of previous attacks ordered by similarity or distance.  

## Common IPs
The amount of common IPs with previously recorded attacks is another important metric.
When a new attack shares a significant portion of IPs with another attack, it is a plausible sign that a single botnet is behind both attacks.  

```python  
# common ips with other attacks  
tools.calculate_common_ips(  
    incidents1 = [29,30], # incidents to explore  
    id_attack = 1, # attack to explore(use -1 for all attacks)  
    incidents2 = [36,37,39,40] # incidents to compare with  
)  
```  

The output is a list of attacks, ordered by the portion of common IPs.  
* The first number - "identical" - is the total number of common identical IPs
* The second number - % of attack - is the portion of identical IPs in the target attack
* The third number - % of incident IPs - is the portion of identical IPs in the incident botnet

```python  
Intersection with incidents:  
[36, 37, 39, 40]  

========================== Attack 1:  
Num IPs in the attack 13857:  

__________ Incident 36:  
Num IPs in the incident 111:  
# identical   IPs: 134  
% of attack   IPs: 5.00%   
% of incident IPs: 77.00%  

__________ Incident 37:  
Num IPs in the incident 2720:  
# identical   IPs: 4567  
% of attack   IPs: 12.00%  
% of incident IPs: 7.00%  
```








