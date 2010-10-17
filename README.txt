
log2georss v0.01
####################
Script to parse a log file and generate a georss file showing latitude, longitude, country and city of ips registered in the log. Right now it just support apache logs. 

Install
###################
You need python with pyrss2gen module (apt-get install python-pyrss2gen in debian-based systems). This script has only been tested in linux.

Usage
###################
execute ./log2georss.py -h for help

examples:

	./log2georss.py -d /var/log -l auth.log -L ssh -o /tmp/test_ssh.xml -t 5400000
	



