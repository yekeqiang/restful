# -*- coding: utf-8 -*- 

from dns import resolver,reversename
from dns.exception import DNSException, SyntaxError
import dns.resolver


addr = reversename.from_address("10.10.1.8")

try:
    psd = resolver.query(addr,"PTR")
    rrset_ptr = psd.rrset
    print rrset_ptr
    name = str(resolver.query(addr,"PTR")[0])
except DNSException:
    print 'addr:', addr, 'is not valid'


#print "the addr is: %s\n" % addr 
#print "the name is: %s\n" % name 
ip = 'gd6-test-005'
# 无法查询 ptr 记录
try:

    answers = dns.resolver.query(ip, 'A')
except DNSException: 
    print 'ip:', ip, 'is not valid'
    exit()

rrset = answers.rrset
qname = answers.qname
expiration = answers.expiration
canonical_name = answers.canonical_name
rdclass = answers.rdclass
rdtype = answers.rdtype
response = answers.response
rcode = response.rcode()
print "the rrset is: %s\n" % rrset
print "the qname is: %s\n" % qname
print "the expiration is: %s\n" % expiration
print "the canonical is: %s\n" % canonical_name
print "the rdclass is: %s\n" % rdclass
print "the rdtype is: %s\n" % rdtype
print "the response is: %s\n" % response
print "the rcode is: %s" % rcode
