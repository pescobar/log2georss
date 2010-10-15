#!/usr/bin/env python
# -*- coding: utf-8 -*-

#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.

#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details. 
#   http://www.gnu.org/licenses/


#   http://gitorious.org/log2georss



import optparse, sys, os, time, gzip, re, cPickle, datetime
from urllib import urlopen
from PyRSS2Gen import *

#pylint: disable-msg=C0301

def main():

    """ main function """
    
    global quiet


    # by default I will save file with cached ips in same dir
    # where the script resides
    cached_ips_file = sys.path[0] + '/' + 'ip_locations.pickle'

    rssitemtitle = ''

    quiet, logsdir, logname,  outputfile, timespan, rssitemtitle, georssurl, = parse_input()

    if rssitemtitle == '':
        rssitemtitle = logname 

    logfiles = get_logfiles(logsdir, logname, timespan)

    accessDict = parse_apache_log(logfiles, timespan, cached_ips_file)

    generate_georss(accessDict, logname, rssitemtitle, georssurl, outputfile) 


def parse_input():
     
    
    """parse input args and show help"""
    
    desc = """ Generate georss files from apache logs """ 
    parser = optparse.OptionParser("usage: %prog [-q] [-d logsdir] [-l logname]"
                                   "[-o output_georss_file.xml]",description=desc)
    
    parser.add_option("-q", action="store_true", dest="quiet", default=False,
                     help="run silently")

    parser.add_option("-d", "--dir", dest="logsdir",
                     default="/var/log/apache2/", type="string",
                     help="directory to look for apache logs. Default is "
                     "/var/log/apache2/")

    parser.add_option("-l", "--logname", dest="logname",
                      default="access.log", type="string",
                      help="apache log to parse. Default is "
                      "access.log")

    parser.add_option("-o", "--output", dest="outputfile",
                     default="/tmp/georss.xml", type="string",
                     help="ouput georss file. Default is"
                     "/tmp/georss.xml")

    parser.add_option("-t", "--timespan", dest="timespan", default=3600,
                     type="int", help="set timespan in seconds. Default is"
                     " 3600 (1 hour)")

    parser.add_option("-T", "--title", dest="rssitemtitle",
                      default="", type="string",
                      help="title for google maps pop-ups")
 

    parser.add_option("-u", "--url", dest="georssurl",
                      default="", type="string",
                      help="url for google maps pop-ups title")




    (options, args) = parser.parse_args()

    #if len(args) != 2:
        #    parser.error("incorrect number of arguments")
        #    parser.print_help() 
    quiet = options.quiet
    logsdir = options.logsdir
    # add final slash
    if not logsdir.endswith('/'):
        logsdir = logsdir + '/'
    logname = options.logname
    outputfile = options.outputfile
    timespan = options.timespan
    rssitemtitle = options.rssitemtitle
    georssurl = options.georssurl
    return quiet, logsdir, logname, outputfile, timespan, rssitemtitle, georssurl



def get_logfiles(logsdir, logname, timespan):
    """Returns a list of the logfiles to process"""

    try:
        logfiles = [filename for filename in os.listdir(logsdir) \
                  if filename.startswith(logname)]
    except IOError:
        print >> sys.stderr, 'ERROR: cannot open %s' % logsdir

    def comp(x, y):
        """ sort log files based on extensions (1,2...3...gz..)"""
        if x.endswith('.log'): return -1
        if y.endswith('.log'): return 1 
        n1, n2 = int(x.split('.')[2]), int(y.split('.')[2])
        if n1 > n2: return 1    
        if n1 < n2: return -1    
        return 0    
                                                                         
    if not logfiles:                                                        
        print logname + ' not found in directory ' + logsdir
        sys.exit()                                                       
    else:
        logfiles.sort(comp)
        return logfiles                                                     

def geolocalize_from_web(ip):
 
    """Returns latitude, longitude, city, country and countryCode 
    corresponding to an IP"""

    if ip.startswith('172.24'):  # local address, from CIPF :)
        return 39.29, -0.22, 'Valencia', 'Spain', 'ES'  # coordinates of Valencia

    # another url we can use for gelocation.
    # parsing properly, of course
    #url = 'http://api.hostip.info/get_html.php?ip=%s&position=true' % ip

    # url to ask ip2location.com
    url='http://ipinfodb.com/ip_query.php?ip=%s&output=raw&timezone=false' % ip

    try:
        geoinfo = urlopen(url).readlines() 
        print geoinfo
    except IOError:
        print >>sys.stderr, 'ERROR: cannot open url %s' % url
        return 0, 0, '', '', ''


    if geoinfo[0].split(",")[1].find("OK")!=-1 :
    
        try:
            countryCode = (geoinfo[0].split(",")[2])
            if len(countryCode) == 0:
                countryCode = ''
            
            country = (geoinfo[0].split(",")[3])
            if len(country) == 0:
                country = ''
            city = (geoinfo[0].split(",")[6])
            if len(city) == 0:
                city = ''

            latitude = float(geoinfo[0].split(",")[8])
            longitude = float(geoinfo[0].split(",")[9])
        except:
            print >>sys.stderr, 'WARNING: Cannot find coordinates of IP', ip
            return 0, 0, '','', ''

    else:
        print >>sys.stderr, 'WARNING: Cannot find coordinates of IP', ip
        return 0, 0, '','',''

    return latitude, longitude, city, country, countryCode

def parse_apache_log(logfiles, timespan, cached_ips_file):

    """ return a dictionary with ips as keys.
    Each ip has associated a tuple containing 
    tool,accessDate,lat,lon,city,country """ 

    t_now = time.time()  # current time (in seconds)
    accessDict = {} # dictionary to save accesses

    # Load file with latitude and longitude of already known IPs.
    try:
        known_locations = cPickle.load(open(cached_ips_file))
        if not quiet:
            print 'retrieved ' + str(len(known_locations)) + ' cached ips ' \
            'from ' + cached_ips_file
            
    
    except:
        known_locations = {}
        if not quiet:
            print 'not found previous saved IPs in disk. After parsing ' \
            'will save cached ips in ' + cached_ips_file

    parsedLines = 0
    cachedIps = 0
    newIps = 0

    for filename in logfiles:
        # we only process uncompressed apache logs for performance. 
        # python gzip module don´t allow seek to last line so we would have
        # to decompress .gz log files before processing which can be quit 
        # resource consuming. TODO: improve this
        if not filename.endswith('.gz'):
        
            if not quiet:
                print 'parsing ' + filename + ' with timespan ' + str(timespan)

            # use xreverse class to parse log from last line.
            # better performance than tac utility and is os independent
            for line in xreverse(open(filename,'rt')):

                f = line.split(None, 4)    
                parsedLines += 1
                
                try:                       
                    ip = f[0].strip()  # the IP is the first field
                except:                                           
                    continue                                      

                try:
                    # take date from third field
                    date = f[3].strip()                                                             
                    date = date.lstrip('[')                                                       

                except:
                    continue
                                
                if ip == "-":
                    continue   
                elif not re.match("\d+\.\d+\.\d+\.\d+",ip):
                    print filename, line             
                    continue                               
                                                               
                try:                                       
                    t = time.mktime(time.strptime(f[3][1:],
                                                 '%d/%b/%Y:%H:%M:%S'))
                except ValueError:  # apache can put a wrong date entry
                    print >>sys.stderr, 'WARNING: malformed date %s' % f[3][1:]
                    continue                                                   
                except IndexError:                                             
                    print >>sys.stderr, 'WARNING: malformed line:', f          
                    continue                                                   

                # be sure to add just one entry for each ip in the log
                # in the accessDict
                if ip not in accessDict:

                    # if ip is not cached in known_locations dict,
                    # I ask webservice for lat,lon....
                    if ip not in known_locations:
                        lat, lon, city, country, countryCode = geolocalize_from_web(ip)
                        time.sleep(0.5)
                        tupla = (date,lat,lon,city,country,countryCode)
                        accessDict[ip] = tupla
                        newIps += 1
                        if not quiet:
                            print 'resolving lat from webservice ' + ip + ' ' +  str(tupla)

                    # if ip is cached I take it from known_locations
                    # I take everything from know_locations dict excepting date
                    else:
                        lat = known_locations[ip][1]
                        lon = known_locations[ip][2]
                        city = known_locations[ip][3]
                        country = known_locations[ip][4]
                        countryCode = known_locations[ip][5]
                        tupla = (date, lat, lon, city, country, countryCode)
                        if not quiet:
                            print 'getting info from cached known_locations ' + ip + ' ' + str(tupla)
                        accessDict[ip] = tupla
                        cachedIps += 1
                        #print '***********************************'
                        #print ip + str(tupla)

                    # stop parsing this log when arrived to timespan
                    if t_now - t > timespan:
                        break

        #print known_locations
        #print len(known_locations)

    if not quiet:
        print str(parsedLines) + ' parsed lines from ' + filename
        print 'retrieved ' + str(len(known_locations)) + ' ips previously cached'\
                + ' from ' + cached_ips_file
        print str(len(accessDict)) + ' different ips parsed in this log. so one entry in the rss for each one'
        print str(newIps) + ' ip are new, so geolocalized by webservice'
        print str(cachedIps) + ' were previously cached'

    # merge accessDict with known_locations
    # to save in disk later......
    known_locations.update(accessDict)

    # Save file with latitude and longitude of already known IPs.
    try:
        #Pickle.dump(known_locations, open('/tmp/ip_locations.pickle', 'wt'))
        cPickle.dump(known_locations, open(cached_ips_file, 'wt'))
        if not quiet:
            print 'saved a total of ' + str(len(known_locations)) + ' ips to '\
                   +  cached_ips_file
            cachedsize = os.path.getsize(cached_ips_file)
            print cached_ips_file + " = %0.1f MB" % (cachedsize/(1024*1024.0))
            
    except:
        print 'problem saving known_locations to disk'
    
    return accessDict

def generate_georss(accessDict, logname, rssitemtitle, georssurl, outputfile):
    """ generate the georss and an entry in the georss for each
        ip in the accessDict """

    # will save in this list all georssitems in the georss
    rssitems_list = []
    title = ''

    # generate an rssitem for each ip in the accessDict
    # and save it in rssitems_list
    for (key,value) in accessDict.iteritems():
        # parse date for nice output in gmap pop-up
        date = value[0].split(':')
        date = date[0] +'<br>'+ date[1] +':'+ date[2]+' GMT +1'
        city = str(value[3])
        country = str(value[4])
        lat = value[1]
        lon = value[2]

        if rssitemtitle == '':
            title = logname
        
        if georssurl == '':
            title = logname
        else:
            title = '<a href=\"'+georssurl+'\" target=\"_blank\">'+rssitemtitle+'</a>'
            
        newgeorss = GeoRSSItem(
            title = title,
        # description is info showed in the gmap pop-up. It
        # accepts html. Now showing date + city + country
            description= date + '<br>'+ city +'<br>'+ country,
            geo_lat= lat,
            geo_lon= lon)
        # add rssitem to the list
        rssitems_list.append(newgeorss)

    #print 'rssitem list'
    #print len(rssitems_list)

    # create georss 
    rss = GeoRSS(
       title = "georss",
       link = "http://gitorious.org/log2georss",
       description = "Feed showing location of ips registered in the log",

       lastBuildDate = datetime.datetime.now(),

       items = rssitems_list)

    # write georss file to disk
    try:
        print ' saving georss file to ' + outputfile
        rss.write_xml(open(outputfile, "w"))
    except:
        print ' problem saving georss'        


class GeoRSS(RSS2):
    rss_attrs = {
        "version": "2.0",
        "xmlns:geo": "http://www.w3.org/2003/01/geo/wgs84_pos#",
    }

    def publish_extensions(self, handler):
        if hasattr(self, 'geo_lat'):
            _opt_element(handler, "geo:lat", self.geo_lat)
        if hasattr(self, 'geo_long'):
            _opt_element(handler, "geo:long", self.geo_long)


class GeoRSSItem(RSSItem):
    def __init__(self, **args ):
        self.geo_lat = IntElement("geo:lat", args.pop("geo_lat", None))
        self.geo_lon = IntElement("geo:long", args.pop("geo_lon", None))

        RSSItem.__init__(self, **args)


# xreverse class - copyright 2004 Michael D. Stenner <mstenner@ece.arizona.edu>
# license: LGPL

class xreverse:
    def __init__(self, file_object, buf_size=1024*8):
        self.fo = fo = file_object
        fo.seek(0, 2)        # go to the end of the file
        self.pos = fo.tell() # where we are 
        self.buffer = ''     # data buffer
        self.lbuf = []       # buffer for parsed lines
        self.done = 0        # we've read the last line
        self.jump = -1 * buf_size
        
        while 1:
            try:            fo.seek(self.jump, 1)
            except IOError: fo.seek(0)
            new_position = fo.tell()
            new = fo.read(self.pos - new_position)
            fo.seek(new_position)
            self.pos = new_position

            self.buffer = new + self.buffer
            if '\n' in new: break
            if self.pos == 0: return self.buffer

        nl = self.buffer.split('\n')
        nlb = [ i + '\n' for i in nl[1:-1] ]
        if not self.buffer[-1] == '\n': nlb.append(nl[-1])
        self.buffer = nl[0]
        self.lbuf = nlb

    def __iter__(self): return self

    def next(self):
        try:
            return self.lbuf.pop()
        except IndexError:
            fo = self.fo
            while 1:
                #get the next chunk of data
                try:            fo.seek(self.jump, 1)
                except IOError: fo.seek(0)
                new_position = fo.tell()
                new = fo.read(self.pos - new_position)
                fo.seek(new_position)
                self.pos = new_position

                nl = (new + self.buffer).split('\n')
                self.buffer = nl.pop(0)
                self.lbuf = [ i + '\n' for i in nl ]

                if self.lbuf: return self.lbuf.pop()
                elif self.pos == 0:
                    if self.done:
                        raise StopIteration
                    else:
                        self.done = 1
                        return self.buffer + '\n'


if __name__ == '__main__':
    #import cProfile
    #cProfile.run(main())
    main()
      
