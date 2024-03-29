
log2georss v0.01
https://github.com/pescobar/log2georss
pescobar001 AT gmail DOT com
####################

Script to parse a log file and generate a georss file showing latitude, longitude, country and city of ips registered in the log. Supports apache access.log and sshd auth.log

Geolocation info is taken from http://ipinfodb.com 
Since ipinfodb.com api change you need to register on the website to get an api key. Once registered on the website and obtained your api key edit the script log2georss.py and set the global var ipinfo_db_api_key with your key


Install		
###################
You only need python and the pyrss2gen module (apt-get install python-pyrss2gen in debian-based systems).
This script has only been tested in linux (ubuntu with python 2.6 and debian lenny with python 2.5). Any feedback about testing in other environments is welcome.


Usage
###################
run ./log2georss.py -h for help

examples:

	$> ./log2georss.py -d /var/log/apache2 -l access.log -L apache -o apache_georss.xml -t 54000

	$> ./log2georss.py -d /var/log -l auth.log -L ssh -o /tmp/test_ssh.xml -t 5400000

The easiest way to see your georss in google maps is by hosting it in a web server and pasting the georss url in google map search bar.

You also have some basic examples of showing your georss in google maps or openlayers in "html-example" directory. You will need to add your google maps api key to the file "google-maps-georss.html" to make it work. For more complex maps check google maps api docs or openlayers docs.
http://code.google.com/apis/maps/signup.html

You can also integrate your georss in drupal by using the "mapping kit" module.
http://drupal.org/project/mappingkit



TODO
###################
Support gzip files. Python gzip modules doesn´t alow to seek to last position to start parsing last line and decompress full apache logs can be quite resource consuming.


Feedback is welcome.
pescobar001 AT gmail DOT com

