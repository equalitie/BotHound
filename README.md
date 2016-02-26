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
  
## Install Jupyter
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
 
## Basic Usage

### Creating incidents
Incidents might be created 

* Manually using Adminer  
* Automatically using bothound. Bothound creates incindets based on messages from GreyMemory anomaly detector.

### Running Bothound

* To run bothound:  
cd src
python bothound.py

### Getting data from Elastic Search and calculating features
1. Set "processed" column to 1 for the incidents you are willing to update.
2. Run python session_computer.py

### Clustering 
To run Jupyter

1. Run Jupyter on server from the folder with the ipynb:    
jupyter notebook --no-browser --port=8889  
2. Run SSH tunnel on your local machine    
ssh -N -L 8889:127.0.0.1:8889 user@server -p 2223  
3. Open http://127.0.0.1:8889  
4. Open src/Clustering.ipynb  

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

### Classification of incidents
Not implemented yet.

### Botnet profiling
Not implemented yet.
