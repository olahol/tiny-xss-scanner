""" Header """
"""
Name: Tiny XSS Scanner
Author(s): olahol
"""

""" Imports """
import urllib2, re, sys 
from urllib import urlencode
from cookielib import CookieJar
from lxml.html import fromstring
from time import sleep

""" Reporting """
def red(s):
    return "\033[31m%s\033[0m" % s
    
def msg(s):
    print "%% " + "%s" % s

def out(s):
    print "--- " + s

""" Xss """
class Xss(object):
    def __init__(self, url, magic = 81512, verbose = True, wait = 2, around = 30):
        self.magic   = str(magic)
        self.verbose = verbose 
        self.wait    = wait
        self.around  = around
        self.xss   = "'';!--\"<" + self.magic + ">=&{()}"
        self.url   = url
        self.get   = []
        self.post  = []
        self.headers = [ ("Content-type", "application/x-www-form-urlencoded")
                        , ('User-Agent', 'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.0.14) Gecko/2009082706 Firefox/3.0.14')
                        , ("Accept", "text/plain") ]
        self.cj     = CookieJar()
        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cj))
        self.opener.addheaders = self.headers
        self.vectors = 0

    def parse(self):
        links = {}
        resp  = self.opener.open(self.url).read()
        doc   = fromstring(resp)

        doc.make_links_absolute(self.url)

        for (el, attr, link, pos) in doc.iterlinks():
            href = link.split("?")
            if len(href) == 2:
                action, fields = link.split("?")
                if action not in links:
                    links[action] = {}
                for field in fields.split("&"):
                    name, value = field.split("=")
                    links[action][name] = value

        for action in links:
            for field, value in links[action].iteritems():
                params        = dict(links[action])
                params[field] = self.xss
                request       = action + "?" + urlencode(params)
                self.get.append(request)

        for form in doc.forms:
            for field, value in form.form_values():
                params        = dict(form.form_values())
                params[field] = self.xss
                action  = form.action
                if action == None: action = ""
                request = action + "?" + urlencode(params)
                method  = form.method.lower()
                if method == "post":
                    self.post.append((action, urlencode(params)))
                else:
                    self.get.append(request)

        self.vectors = len(self.get) + len(self.post)

    def scan(self):
        msg("Scanning " + str(self.vectors) + " vector(s)")

        for request in self.get:
            msg("GET " + request)
            try:
                resp = self.opener.open(request).read()
                self.print_match(resp)
                sleep(self.wait)
            except KeyboardInterrupt:
                msg("Bye.")
                sys.exit()
            except:
                out("Error!")

        for action, params in self.post:
            msg("POST " + action + "?" + params)
            try:
                req      = urllib2.Request(action, params)
                response = urllib2.urlopen(req)
                resp     = response.read()
                self.print_match(resp)
                sleep(self.wait)
            except KeyboardInterrupt:
                msg("Bye.")
                sys.exit()
            except:
                out("Error!")

    def print_match(self, resp):
        for n, m in enumerate(re.finditer(self.magic, resp)):
            start, end = m.span()
            start_new = start - self.around
            end_new   = end + self.around
            if start_new < 0: start_new = 0
            if end_new >= len(resp) - 1: end_new = len(resp) - 1 
            data = resp[start_new:end_new].replace("\n", red("\\n"))
            out(str(n+1) + ", " + data)

""" Main """
if __name__ == "__main__":
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-m", "--magic")
    parser.add_option("-w", "--wait")
    parser.add_option("-a", "--around")
    (options, args) = parser.parse_args()
    if len(args) == 1:
        xss = Xss(args[0])
        xss.parse()
        xss.scan()
    else:
        print "Error: %s takes one argument (the website)" % sys.argv[0]
