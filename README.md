# PhishingKitHunter
*Find phishing kits which use your brand/organization's files and image.*

**PhishingKitHunter** (or *PKHunter*) is a tool made for identifying phishing kits URLs used in phishing campains targeting your customers and using some of your own website files (as CSS, JS, ...).
This tool - write in Python 3 - is based on the analysis of referer's URL which GET particular files on the legitimate website (as some style content) or redirect user after the phishing session. Log files (should) contains the referer URL where the user come from and where the phishing kit is deployed.
**PhishingKitHunter** parse your logs file to identify particular and non-legitimate referers trying to get legitimate pages based on regular expressions you put into PhishingKitHunter's config file.

## Features
- find URL where a phishing kit is deployed
- find if the phishing kit is still up and running
- generate a CSV report useful for external usage
- use a hash of the phishing kit's page to identify the kit
- use a timestamp for history
- can use HTTP or SOCKS5 proxy
- WHOIS enrichment to console and CSV report

## Usage
~~~
$ ./PhishingKitHunter.py -i LogFile2017.log -o PKHunter-report-20170502-013307.csv -c conf/test.conf

  _ \  |  / |   |             |            
 |   | ' /  |   | |   | __ \  __|  _ \  __|
 ___/  . \  ___ | |   | |   | |    __/ |   
_|    _|\_\_|  _|\__,_|_|  _|\__|\___|_|   

-= Phishing Kit Hunter - v0.8.1 =-

[+] http://badscam.org/includes/ap/?a=2
		|   Timestamp: 01/May/2017:13:00:03
		| HTTP status: can't connect (HTTP Error 404: Not Found)
[+] http://scamme.com/aple/985884e5b60732b1245fdfaf2a49cdfe/
		|   Timestamp: 01/May/2017:13:00:49
		| HTTP status: can't connect (<urlopen error [Errno -2] Name or service not known>)
[+] http://badscam-er.com/eb/?e=4
		|   Timestamp: 01/May/2017:13:01:06
		| HTTP status: can't connect (<urlopen error [Errno -2] Name or service not known>)
[+] http://assur.cam.tech/scam/brand/new/2bd5a55bc5e768e530d8bda80a9b8593/
		|   Timestamp: 01/May/2017:13:01:14
		| HTTP status: UP
		| HTTP shash : 0032588b8d93a807cf0f48a806ccf125677503a6fabe4105a6dc69e81ace6091
                | DOMAIN registrar: ASCIO TECHNOLOGIES, INC. DANMARK - FILIAL AF ASCIO TECHNOLOGIES, INC. USA
                | DOMAIN creation date: 2008-07-10 00:00:00
                | DOMAIN expiration date: 2017-07-10 00:00:00
[+] http://phish-other.eu/assur/big/phish/2be1c6afdbfc065c410d36ba88e7e4c9/
		|   Timestamp: 01/May/2017:13:01:15
		| HTTP status: UP
		| HTTP shash : 2a545c4d321e3b3cbb34af62e6e6fbfbdbc00a400bf70280cb00f4f6bb0eac44
                | DOMAIN registrar: Hostmaster Strato Rechenzentrum
                | DOMAIN creation date: None found
                | DOMAIN expiration date: None found
697475it [06:41, 1208.14it/s]
~~~

## Help
~~~
$ ./PhishingKitHunter.py --help

  _ \  |  / |   |             |            
 |   | ' /  |   | |   | __ \  __|  _ \  __|
 ___/  . \  ___ | |   | |   | |    __/ |   
_|    _|\_\_|  _|\__,_|_|  _|\__|\___|_|    

-= Phishing Kit Hunter - v0.8.1 =-

			-h --help   Prints this
			-i --ifile    Input logfile to analyse
			-o --ofile    Output CSV report file (default: ./PKHunter-report-'date'-'hour'.csv)
			-c --config   Configuration file to use (default: ./conf/defaults.conf)
~~~

## CSV report example
~~~
$ cat ./PKHunter-report-20170502-013307.csv
PK_URL;Domain;HTTP_sha256;HTTP_status;date;domain registrar;domain creation date;domain creation date;domain expiration date
http://badscam.org/includes/ap/?a=2;badscam.org;;can't connect (HTTP Error 404: Not Found);01/May/2017:13:00:03;;;
http://assur.cam.tech/scam/brand/new/2bd5a55bc5e768e530d8bda80a9b8593/;assur.cam.tech;0032588b8d93a807cf0f48a806ccf125677503a6fabe4105a6dc69e81ace6091;UP;01/May/2017:13:01:14;None found;None found;Hostmaster Strato Rechenzentrum
[...]
~~~

## Requirements
* Python 3
* tqdm
* csv
* python-whois

## Install
Install the requirements
~~~
pip3 install -r requirements.txt
~~~

## Configure
Please read the conf/default.conf file to learn how to configure PhishingKitHunter.

## Docker
You can use the Dockerfile to create a Docker container which automaticaly git clone this repository.
This is based on the latest light Phusion distrib, get packages needed to get and execute **PhishingKitHunter**.

Build the container:
~~~
$ docker build tad/pkhunter .
~~~

Start the container with some options (as your local log files repository):
~~~
$ docker run -d -P --name PKHunter --volume /var/log:/opt/logfiles tad/pkhunter
~~~

You can now execute  shell and start your analysis:
~~~
$ docker exec -ti tad/pkhunter /bin/bash
~~~
