# PhishingKitHunter
*Find phishing kits which use your brand/organization's files and image.*

**PhishingKitHunter** (or *PKHunter*) is a tool made for identifying phishing kits URLs used in phishing campains targeting your customers and using some of your own website files (as CSS, JS, ...).
This tool - write in Python 3 - is based on the analysis of referer's URL which GET particular files on the legitimate website (as some style content) or redirect user after the phishing session. Log files (should) contains the referer URL where the user come from and where the phishing kit is deployed.
**PhishingKitHunter** parse your logs file to identify particular and non-legitimate referers trying to get legitimate pages based on regular expressions you put into PhishingKitHunter's config file.

## Features
- find URL where a phishing kit is deployed
- find if the phishing kit is still up and running
- generate a JSON report usefull for external usage
- use a hash of the phishing kit's page to identify the kit
- use a timestamp for history
- can use HTTP or SOCKS5 proxy

## Usage
~~~
$ ./PhishingKitHunter-0.6.py -i LogFile2017.log -o PKHunter-report-20170502-013307.json -c conf/test.conf

  _ \  |  / |   |             |            
 |   | ' /  |   | |   | __ \  __|  _ \  __|
 ___/  . \  ___ | |   | |   | |    __/ |   
_|    _|\_\_|  _|\__,_|_|  _|\__|\___|_|   

-= Phishing Kit Hunter - v0.6b =-

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
[+] http://phish-other.eu/assur/big/phish/2be1c6afdbfc065c410d36ba88e7e4c9/
		|   Timestamp: 01/May/2017:13:01:15
		| HTTP status: UP
		| HTTP shash : 2a545c4d321e3b3cbb34af62e6e6fbfbdbc00a400bf70280cb00f4f6bb0eac44
697475it [06:41, 1208.14it/s]
~~~

## Help
~~~
$ ./PhishingKitHunter-0.6.py --help

  _ \  |  / |   |             |            
 |   | ' /  |   | |   | __ \  __|  _ \  __|
 ___/  . \  ___ | |   | |   | |    __/ |   
_|    _|\_\_|  _|\__,_|_|  _|\__|\___|_|    

-= Phishing Kit Hunter - v0.6b =-

			-h --help   Prints this
			-i --ifile    Input logfile to analyse
			-o --ofile    Output JSON report file (default: ./PKHunter-report-'date'-'hour'.json)
			-c --config   Configuration file to use (default: ./conf/defaults.conf)
~~~

## JSON report example
~~~
$ cat ./PKHunter-report-20170502-013307.json

{
    "PK_URL": "http://badscam.org/includes/ap/?a=2",
    "PK_info": {
        "Domain": "badscam.org",
        "HTTP_sha256": "",
        "HTTP_status": "can't connect (HTTP Error 404: Not Found)",
        "date": "01/May/2017:13:00:03"
    }
}{
    "PK_URL": "http://assur.cam.tech/scam/brand/new/2bd5a55bc5e768e530d8bda80a9b8593/",
    "PK_info": {
        "Domain": "assur.cam.tech",
        "HTTP_sha256": "0032588b8d93a807cf0f48a806ccf125677503a6fabe4105a6dc69e81ace6091",
        "HTTP_status": "UP",
        "date": "01/May/2017:13:01:14"
    }
}
[...]
~~~

## Requirements
* Python 3
* requests
* tqdm
* json
* PySocks

## Install
Install the requirements
~~~
pip install -r requirements.txt
~~~

## Configure
Please read the conf/default.conf file to learn how to configure PhishingKitHunter.
