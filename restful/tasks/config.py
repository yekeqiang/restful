#coding:utf-8
import ConfigParser

def getDnsKeyFile(conf_path):
    cf = ConfigParser.ConfigParser()
    cf.read(conf_path)
    ##sec = cf.sections()
    #pos = cf.options("KEY")
    conf_file = cf.get("KEY","keyfile")
    return conf_file

def getDnsHost(conf_path):
    cf = ConfigParser.ConfigParser()
    cf.read(conf_path)
    dnshost = cf.get("HOST","dnshost")
    return dnshost

def getDnsZone(conf_path):
    cf = ConfigParser.ConfigParser()
    cf.read(conf_path)
    domain = cf.get("ZONE","hostZone")
    return domain
