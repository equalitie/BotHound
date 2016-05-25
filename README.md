BotHound
=======

Automatic attack detector and botnet classifier
-----------

# Installation

## Libraries
The following libraries should be installed:

* [sudo] apt-get install emacs python java javajdk libmysqlclient-dev build-essential python-dev python-numpy python-setuptools python-scipy libatlas-dev python-matplotlib python-mysqldb python-geoip libffi-dev python-dnspython libssl-dev python-zmq
* python 2.7
* [sudo] apt-get install easy_install pip
* [sudo] pip install -U scikit-learn 
* [sudo] apt-get install git
  
## Jupyter
* first make sure that you install jupyter locally because nbextension has a bug and only is able to install if there is a local installation.  
sudo pip install jupyter --user

* install jupyter system wide  
sudo pip install jupyter

* install jupyter nbextensions  
pip install https://github.com/ipython-contrib/IPython-notebook-extensions/archive/master.zip

* by mistake it copies the file in the local folder. Copy the files to the system wide folder.  
sudo cp /root/.local/share/jupyter /usr/local/share  
sudo chmod -R a+r /usr/local/share/jupyter 

## Get Source Code 
* git clone https://github.com/equalitie/bothound  
* cd bothound/

## Install Packages
Install required packages from requirements.txt:  

* pip install -r requirements.txt  

## Configuration 
You need to create a configuration file bothound.yaml

1. Make a copy of conf/rename_me_to_bothound.yaml  
2. Rename the copy to bothound.yaml  
3. Update the file with your credentials 

# Initialization

## Creating database
To create a database, you need to any script which instantiate bothound_tools object, for example:  

* cd src  
* python session_computer.py  

Make sure the database and the tables are created successfully.

## Running Jupyter
1. Make sure Jupyter instance is running on the bothound server. 
To run the instance, use:  
jupyter notebook --no-browser --port=8889
2. Establish a tunnel to Jupyter instance from your local computer:  
ssh -N -L 8889:127.0.0.1:8889 anton@bothound.deflect.ca
3. Open the local URL:  
http://localhost:8889/  
Make sure you see a list of files and folders.

## Incidents 
Incidents are created manually using Adminer interface. In the future incidents will be created automaically based on messages from GreyMemory anomaly detector.

### Creating incidents 
* Insert a new record into into "incidents" table. 
* Make sure you filled at least "start", "stop", "target" fields.
* The target URL should not contain "www." at the beginning. If you have multiply targets, you can add them sepatated by comma.
* Set "process" field to 1.

### Creating incidents from nginx logs
* Insert a new record into into "incidents" table. 
* Make sure you filled "file_name" with the full path to a nginx log file.
* Set "process" field to 1.

## Sessions
### Session Computer
Session Computer calculates sessions for all the records in incidents table containing 1 in the "Process" field.

* Run session computer with "python session_computer.py". 
* Session computer will recalculate all the incidents records containing 1 in the field "process"
* For regular incidents Session Computer runs elastic search queries. For nginx incidents Session Computer will parse the corresponding log file.
* The sessions will be stored in "sessions" table

### IP Encryption
For security reasons Bothound stores only encrypted IPs in the session table (fields "ip_encrypted", "ip_iv","ip_tag"). 
The hash of the IP is also stored in the field "ip".
The encryption key is set in the configuration file "conf/bothound.yaml"("encryption_passphrase").
Bothound suports multiply encryption keys. "Encryption" table contains the hash value of the key which was used to encrypt IPs of an incident. 

In order to get the decrypted IPs of the incident use extract_attack_ips() function in bothound_tools.py 

## Attacks
Bothound uses clustering methods in order to separate attackers from regular traffic.
This process of labeling a subset of incident sessions as an attack is manual. 
The user opens a Jyputer notebook, chooses an incident, clusters the sessions with different clustering algorithms and manually assigns an arbitrary attack number to the selected clusters. 

### Jupyter notebooks
The [Jupyter Notebook](http://jupyter.org/) is a web application that allows you to create and share documents that contain live code, equations, visualizations and explanatory text. 
Notebook contains a list of cells(markdown, python code, graphs). 
Use Shift+Enter to execute a cell.
You can fold/unfold the contect of a cell using an "arrow" character on the left.

### Labeling attackers
1. Open Jupyter interface URL: http://localhost:8889/ 
2. Open src/Clustering.ipynb  
3. Execute Initialization chapter
4. Configuration chapter: change the assignment of variable "id_incident" to your incident number
5. Execute Configuration chapter







Using thes Ipython notebook you can:

* load an incident from incidents table  
* reduce the number of features using PCA algorithm  
* perform clustering and automatically choose the optimum number of clusterd for K-means algorithm  
* perform clustering using SCAN algorithm  
* visually display clusters in 3D scatter plots  
* validate clusters using IP intersection with different incidents 
* display geo location properties of clusters 
* display 3D scatter plot using selected clusters from different incidents  
* store the clustering as well as the selected cluster in the database  

