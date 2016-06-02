BotHound
=======

Automatic DDoS attack detector and botnet classifier
-----------

# Description
Bothound is an automatic DDoS attack detector and botnet classifier. Its purpose is to create a historical classification of the attacks with detailed information regarding the attackers (country-based, time-based, etc.).

Bothound's role is to detect and classify the attacks (incidents), using the anomaly-detection and machine-learning tool Grey Memory. BotHound attack classifier reacts to anomalous detectors and starts gathering live information from the Deflect network. It computes a behaviour vector for all visitors of the network when Grey Memory detects an anomaly. BotHound groups the client IPs in different groups (clusters) using unsupervised machine learning algorithms in order to profile the group of malicious visitors. It uses different measures to tag the groups which are more likely to be attackers. After that, it feeds all the behaviour vectors of bot IPs into a classifier to detect if the botnet has a history of attacking the [Deflect network](https://wiki.deflect.ca/wiki/Main_Page) in the past. It finally generates a report based on its conclusions for Deflect's Sysops and gets feedback to improve its classification performance.

# Installation

## Python
Python 2.7 should be installed

## Libraries
The following libraries should be installed:  

```  
[sudo] apt-get install emacs python java javajdk libmysqlclient-dev build-essential python-dev python-numpy python-setuptools python-scipy libatlas-dev python-matplotlib python-mysqldb python-geoip libffi-dev python-dnspython libssl-dev python-zmq   
[sudo] apt-get install easy_install pip  
[sudo] pip install -U scikit-learn  
[sudo] apt-get install git  
 ```  
 

## Jupyter
* First make sure that you install Jupyter locally because nbextension has a bug and is only able to install if there is a local installation.  
``` 
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
sudo cp /root/.local/share/jupyter /usr/local/share  
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

1. Make a copy of the [example configuration file](conf/rename_me_to_bothound.yaml)  
2. Rename the copy to bothound.yaml  
3. Update the file with your credentials 
	
# Initialization

## Creating a database
To create a database, you need to launch any script which instantiates bothound\_tools object, for example:  
```
cd src  
python session_computer.py  
```

Make sure the database and the tables are created successfully.

## Running Jupyter
1. Make sure the Jupyter instance is running on the Bothound server. 
To run the instance, launch this command:  
```
jupyter notebook --no-browser --port=8889
```
2. Establish a tunnel to the Jupyter instance from your local computer:  
```
ssh -N -L 8889:127.0.0.1:8889 anton@bothound.deflect.ca
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
Incidents are created manually using the Adminer interface. In the future, incidents will be created automaically based on messages from the Grey Memory anomaly detector.

## Creating incidents 
* Insert a new record into the "incidents" table. 
* Make sure you filled at least the "start", "stop" and "target" fields.
* The target URL should not contain "www." at the beginning. If you have multiple targets, you can add them separated by a comma.
* Set "process" field to 1.

## Creating incidents from nginx logs
* Insert a new record into the "incidents" table. 
* Make sure you filled "file_name" with the full path to a nginx log file.
* Set "process" field to 1.

# Sessions
## Session Computer
The Session Computer calculates sessions for all the records in the incidents table containing "1" in the "Process" field.

* Run the Session Computer with 
```
python session_computer.py
```   
* The Session Computer will recalculate all the incident records containing "1" in the "Process" field.
* For regular incidents, the Session Computer runs ElasticSearch queries. For nginx incidents, the Session Computer will parse the corresponding log file.
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

## Jupyter Notebook
The [Jupyter Notebook](http://jupyter.org/) is a web application that allows you to create and share documents that contain live code, equations, visualizations and explanatory text. 
Notebook contains a list of cells (markdown, python code, graphs). 
Use Shift+Enter to execute a cell.
You can fold/unfold the content of a cell using the left "arrow" key.

## Loading incident
* Open Jupyter interface URL: [http://localhost:8889/](http://localhost:8889/)
* Open src/Clustering.ipynb  
* Execute Initialization chapter  
* Configuration chapter: change the assignment of variable "id\_incident = ..." to your incident number  
* Configuration chapter: uncomment the features you want to use: "features = [...]"  
* Execute Configuration chapter  
* Execute "Load Data"chapter 

## Clustering
* Execute DBSCAN Clustering chapter. 
After the clustering is done, you will see a bar plot of clusters. 
Y-axes corresponds to the size of the cluster. Every cluster has its own color from a predefined palette.

* Use plot3() function in the second cell of the chapter to create different 3D scatter plots of the calculated clusters:

```python
plot3([0,1,3], X, clusters, [])  
```
The first argument of this function is an array of indexes of the 3 features to display at the scatter plot. Note that these are the indexes in the array of uncommented features from the "Configuration" chapter. If you have more than 3 uncommented features, choose different indexes and re-execute plot3() cell.

* Choose your features carefully. 
It's always better to experiment and play with different features subsets (uncommented in "Configuration" chapter). Clustering is very sensitive to feature selection. 
Different attacks might have different distinguishable features. 
If you change your features selection in "Configuration" chapter, you must re-execute the "Configuration", "Load Data", and "Clustering" chapters. 

* Double clustering.
In some cases DBSCAN clustering is not good enough. The suspected cluster might have a weird shape and even contain two different botnets. In order to further divide such a cluster you can use the second iteration, which we call "Double Clustering". You should choose the target cluster after the first clustering, as well as the number of clusters for K-Means clustering algorithm.  
The second cell in this chapter is the same plot3() function which displays a 3D scatter plot of double clustering.

```python
plot3([0,1,3], X2, clusters2, [])
```
Note, that you should use X2 and clusters2 arguments.

## Attack saving
* Choose your attack ID(s).
Attack IDs are arbitrary numbers you assign to each botnet. The attack is identified by its incident ID and attack ID.
It is possible to have more than one attack in a single incident. 

* Modify the tools.label\_attack() function arguments  
If you have more than 1 attack number to save, you should add a call to the label/attack() function for every attack.  
For example, for attack #1 you choose cluster #3:  
```python 
tools.label\_attack(id\_incident, attack\_number = 1, selected\_clusters = [3], selected\_clusters2 = [])  
```
If you use double clustering, don't forget to specify the indexes for selected_clusters2.
For example, for attack #1 you will choose cluster #3 and double clusters #4 and #5:   

tools.label\_attack(id\_incident, attack\_number = 1, selected\_clusters = [3], selected\_clusters2 = [4,5])  

* Execute "Save Attack" chapter. 

## Feature exploration
In this section, users can explore the distribution of a single feature over the clusters to verify the quality of the clustering results.  

box\_plot\_feature(clusters, num_clusters = 4, X = X, feature\_index = 2)  

The function will display a boxplot of feature values distribution per cluster.
Using this graph, you can get more insight into the quality of the clustering you used.  
For instance, if you know in advance that the attack you are clustering should have a significant higher hit rate, then you can expect that a proper attack cluster should have a similar high boxplot of "request\_interval" features.

## Common IPs with other incidents
If two attacks share a significant portion of identical IPs, they are likely to belong to the same botnet.

plot\_intersection(clusters, num\_clusters, id\_incident, ips, id\_incident2 = ..., attack2 = -1)  

This function will create a bar plot highlighting portions of the clusters which share identical IPs with another incident (specified by variable id_incident2). It's also possible to specify a particular attack index.

## Countries
This graph explores the country distribution over the clusters. 

## Banjax
Even if an IP was banned during the incident, Bothound does not use this information for clustering.
Nevertheless, the distribution of banned IPs over the clusters might be useful.
This graph will display portions of IPs, banned by Banjax per cluster.
