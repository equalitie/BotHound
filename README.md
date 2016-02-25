BotHound
=======

Automatic attack detector and botnet classifier
-----------

# Installation

## Libraries
The following libraries should be installed:

* $sudo apt-get install emacs python java javajdk libmysqlclient-dev build-essential python-dev python-numpy python-setuptools python-scipy libatlas-dev python-matplotlib python-mysqldb python-geoip libffi-dev python-dnspython
* python 2.7
* [sudo] apt-get install easy_install pip

* [sudo] apt-get install build-essential libssl-dev libffi-dev python-dev
* [sudo] apt-get install python-zmq

* [sudo] pip install -U scikit-learn 

* [sudo] sudo apt-get install build-essential python-dev python-setuptools python-numpy python-scipy
* [sudo] apt-get install git
  
## Source code 

* git clone https://github.com/equalitie/bothound
* cd bothound/

## Packages
Install required packages:

* [sudo] pip install -r requirements.txt  

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

