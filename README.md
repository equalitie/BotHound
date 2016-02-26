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
  
## Install Anaconda
* Download Anaconda installer from [https://www.continuum.io/downloads](https://www.continuum.io/downloads):
* [sudo] bash Anaconda2-2.5.0-Linux-x86_64.sh
Install to /opt/anaconda
* Make sure /opt/anaconda/bin is in the $PATH

## Install Jupyter
* [sudo] conda install jupyter
* pip install https://github.com/ipython-contrib/IPython-notebook-extensions/archive/master.zip

## Get Source Code 
* git clone https://github.com/equalitie/bothound
* cd bothound/

## Install Packages
Install required packages from requirements.txt:
* [sudo] /opt/anaconda/bin/pip install -r requirements.txt  





## Configuration 
You need to create a configuration file bothound.yaml
1. Make a copy of conf/rename_me_to_bothound.yaml
2. Rename the copy to bothound.yaml
3. Update the file with your credentials
 

Inititalize the file:
 $ python vengeance_live_sniffer.py --bindstrings tcp://10.0.1.48:22621

Testing records: 
in a browser, type:

http://deflect.edge/

where deflect.edge is the address of your deflect edge

 # it should print details on the screen


Initialize logfetcher.py

    python src/logfetcher.py

