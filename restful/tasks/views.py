# -*- coding: utf-8 -*-

import re
import socket
import sys

import dns.name
import dns.query
import dns.update
import dns.reversename
import dns.tsigkeyring
import dns.resolver

from dns.exception import DNSException, SyntaxError

from functools import wraps

from flask import abort, Blueprint, jsonify, make_response, request
from flask.ext.restful import Api, fields, marshal, Resource, reqparse

mod = Blueprint('tasks', __name__, url_prefix='/dns/api')
api = Api(mod)

DOMAIN = 'idc.vip.com'
DNSHOST = '127.0.0.1'

KEYRING = dns.tsigkeyring.from_text({
    'update.zones.key': 'z6z4X6TZ/1zsazWf7oT1AA=='
})



check_auth = lambda user, passwd: user == 'admin' and passwd == 'admin'

def requires_auth(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            abort(401)
        return func(*args, **kwargs)
    return decorated


class TaskListAPI(Resource):

    def __init__(self):
        super(TaskListAPI, self).__init__()
        self.parse = reqparse.RequestParser()
        self.parse.add_argument('domain_name', type=str, required=True, help='No domain_name in dns', location='json')
        self.parse.add_argument('domain_ip', type=str, default="", location='json')

    def get(self):
        return jsonify(tasks=[marshal(t, task_fields) for t in tasks])

    @requires_auth
    def post(self):
        args = self.parse.parse_args()
        record_name = args['domain_name']
	record_data = args['domain_ip']
        #record_type = args['rcord_type']
        record_type = "A"
        #ttl = args['ttl']
        ttl = 3600
        #create_reserve = args['is_reserve']
        create_reserve = True
        key_name = KEYRING
        key_file = "/var/named/chroot/etc/Kupdate.zones.key.+157+30577.key"
        zone_name = DOMAIN
        dns_server = DNSHOST
	#rcode = add_zone_record(domain_name, domain_ip)
        #rcode = create_forward_zone_record(dns_server, zone_name, record_name, record_type, record_data, ttl, key_name)
        rcode = create_forward_zone_record(dns_server, zone_name, record_name, record_type, record_data, ttl, key_file)

        if create_reserve: 
            #record = create_reverse_zone_record(dns_server, record_data, record_name, zone_name, ttl, key_name)
            record = create_reverse_zone_record(dns_server, record_data, record_name, zone_name, ttl, key_file)

        if rcode == 0:
            result = 'true'
            return jsonify(domain_name = str(record_name), domain_ip = str(record_data), domain = zone_name, dns_server = dns_server, result = result)
        else:
            return "add the dns_domain %s failed" % record_name       


class TaskAPI(Resource):

    def __init__(self):
        super(TaskAPI, self).__init__()
        self.parse = reqparse.RequestParser()
        self.parse.add_argument('domain_name', type=str, location='json')
        self.parse.add_argument('domain_ip', type=str, location='json')
        self.parse.add_argument('done', type=bool, location='json')

    def get(self, domain_name):
        info = ip_info(domain_name)
        return jsonify(info=str(info), domain_name=str(domain_name))

    @requires_auth
    def put(self):
        args = self.parse.parse_args()
        domain_name = args['domain_name']
        domain_ip = args['domain_ip']
        rcode = modify_zone_record(domain_name, domain_ip)
        if rcode == 0:
            result = 'true'
            return jsonify(domain_name = str(domain_name), domain_ip = str(domain_ip), domain = DOMAIN, dns_server = DNSHOST, result = result)
        else:
            return "update the domain_name %s to the domain_ip %s failed" % (domain_name, domain_ip)


    @requires_auth
    def delete(self):
        args = self.parse.parse_args()
        domain_name = args['domain_name']
        key_file = "/var/named/chroot/etc/Kupdate.zones.key.+157+30577.key"
        rcode = delete_zone_record(domain_name, key_file)
        if rcode == 0:
            result = 'true'
            return jsonify(domain_name = str(domain_name),result = result)
        else:
            return "delete the dns_domain %s failed" % domain_name




def isValidTTL(TTL):
    """ valid the ttl.

    Args:
        String ttl

    Returns:
        TTL
    """
    try:
        TTL = dns.ttl.from_text(TTL)
    except:
        print 'TTL:', TTL, 'is not valid'
        exit()
    return TTL

def isValidPTR(ptr):
    """valid the ip is or not ptr
     Args:
         String: ptr
    
     Returns:
        ptr
    """
    if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}.in-addr.arpa\b', ptr):
        return True
    else:
        print 'Error:', ptr, 'is not a valid PTR record'
        exit()

def isValidV4Addr(Address):
    """valid the ip is or not ipv4
    
    Agrs:
        String: Address
    
    Returns:
        boolean
    """
    try:
        dns.ipv4.inet_aton(Address)
    except socket.error:
        print 'Error:', Address, 'is not a valid IPv4 address'
        exit()
    return True

def isValidV6Addr(Address):
    """valid the ip is or not ipv4
    
    Agrs:
        String: Address
    
    Returns:
        boolean
    """
    try:
        dns.ipv6.inet_aton(Address)
    except SyntaxError:
        print 'Error:', Address, 'is not a valid IPv6 address'
        exit()
    return True


def isValidName(Name):
    """the name maybe domain_name
       valid the name is or not right format
    Args:
       String Name
    
    Returns:
       boolean
    """
    if re.match(r'^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9]\.?)$', Name):
        return True
    else:
        print 'Error:', Name, 'is not a valid name'


#def create_forward_zone_record(dns_server, zone_name, record_name, record_type, record_data, ttl, key_name):
def create_forward_zone_record(dns_server, zone_name, record_name, record_type, record_data, ttl, key_file):
    """ Parse passed elements and determine which records to create.

    Args:
      String dns_server
      String zone_name
      String record_name (just record name, not FQDN)
      String record_type (A, AAAA, etc)
      String record_data (IP address)
      Int ttl
      String key_name (from Key model)

    Return:
      Dict containing {description, output} from record creation
    issue #3: before add the forward record, u need validate if the record is exist，if not exist, return fail, if exist ,return              success，and add the record
    """
    KeyRing = getKey(key_file)
    #update = dns.update.Update(zone_name, keyring = key_name)
    update = dns.update.Update(zone_name, keyring = KeyRing)
    update.replace(record_name, ttl, record_type, record_data)
    response = dns.query.tcp(update, dns_server, timeout=10)
    rcode = response.rcode()
    return rcode

#def create_reverse_zone_record(dns_server, record_data, record_name, zone_name, ttl, key_name):
def create_reverse_zone_record(dns_server, record_data, record_name, zone_name, ttl, key_file):
    """ If requested, create a reverse PTR record.
    Given the forward record created, resolve its underlying IP. Use that to create the reverse record.
    reverse_ip_fqdn ex: 5.0.20.10.in-addr.arpa.
    reverse_ip: 5
    reverse_domain: 0.20.10.in-addr.arpa.
    """
    reverse_ip_fqdn = str(dns.reversename.from_address(record_data))
    # There must be a cleaner way to figure out the ip/domain
    # for this reverse DNS record parsing.
    reverse_ip = re.search(r"([0-9]+).(.*)$", reverse_ip_fqdn).group(1)
    reverse_domain = re.search(r"([0-9]+).(.*)$", reverse_ip_fqdn).group(2)
    rcode = create_forward_zone_record(dns_server, reverse_domain, \
                     reverse_ip, "PTR", "%s.%s." % (record_name, zone_name),\
                     ttl, key_file)
    return rcode

def delete_zone_record(domain_name, key_file):
    """ del DNS zone record from dns server and return rcode.

    Args:
        String domain_name

    Returns:
        String rcode
    """
    dns_server = str(DNSHOST)
    KeyRing = getKey(key_file)
    key_name = 'update.zones.key'
    #dns_update = dns.update.Update(DOMAIN, keyring = KEYRING)
    dns_update = dns.update.Update(DOMAIN, keyring = KeyRing)
    dns_update.delete(str(domain_name))
    response = send_dns_update(dns_update, dns_server, key_name)
    rcode = response.rcode()
    return rcode

def modify_zone_record(domain_name, domain_ip, key_file):
    """modify DNS zone record from dns server and return rcode.

    Args:
        String domain_name
        String domain_ip

    Returns:
        String rcode
    issue #1: when update the forward record, also need update the reserve record
    issue #2: before update the forward record, u need validate if the record is exist，if not exist, return fail, if exist ,return              success，and update the record
    """
    KeyRing = getKey(key_file)
    ttl = 3600
    record_type = "A"
    domain = dns.name.from_text(DOMAIN)
    update = dns.update.Update(DOMAIN, keyring = KeyRing)
    update.delete(str(domain_name))
    update.add(str(domain_name), ttl, record_type, str(domain_ip))
    response = dns.query.tcp(update, DNSHOST)
    rcode = response.rcode()
    return rcode


def ip_info(host_name):
        """Create a dictionary mapping address types to their IP's.
        If an error is encountered, key to error is "Error".
        """
        info = []
        ip_protocol_count = 0
        try:
            for s_family, s_type, s_proto, s_cannoname, s_sockaddr in socket.getaddrinfo(host_name, None):
                if s_family == 2 and s_type == 1:
                    ip_protocol_count += 1
                    info.append(["IPv4 (%d)" % ip_protocol_count, s_sockaddr[0]])
                if s_family == 10 and s_type == 1:
                    ip_protocol_count += 1
                    info.append(["IPv6 (%d)" % ip_protocol_count, s_sockaddr[0]])
        except socket.gaierror, err:
            info.append(["Error", "Unable to resolve %s: %s" % (host_name, err)])

        return info


def send_dns_update(dns_message, dns_server, key_name):
    """ Send DNS message to server and return response.

    Args:
        Update dns_update
        String dns_server
        String key_name

    Returns:
        String response
    """

    try:
        response = dns.query.tcp(dns_message, dns_server)
    except dns.tsig.PeerBadKey:
        response = ("DNS server %s is not configured for TSIG key: %s." %
                  (dns_server, key_name))
    except dns.tsig.PeerBadSignature:
        response = ("DNS server %s did like the TSIG signature we sent. Check key %s "
                  "for correctness." % (dns_server, key_name))

    return response


def lookup_forward_record(domain_name, record_type):
    """lookup the detail reocrd by domain_name
    
    Args:
        String domain_name
    

    Returns:
        rrset  - the full zone record etc:gd6-test-005.idc.vip.com. 3600 IN A 10.10.1.9
        qname  - the full domain name etc:gd6-test-005.idc.vip.com.
        expiration - the expiration time etc: 1403165675.1
        canonical_name - the canonical domain name etc: gd6-test-005.idc.vip.com.
        rdclass - int etc:1
        rdtype - int  etc:1
        rcode - int etc:0
    the response:
    
    the response is: id 62640
    opcode QUERY
    rcode NOERROR
    flags QR AA RD RA
    ;QUESTION
    gd6-test-005.idc.vip.com. IN A
    ;ANSWER
    gd6-test-005.idc.vip.com. 3600 IN A 10.10.1.9
    ;AUTHORITY
    idc.vip.com. 86400 IN NS gd6-conf-auto-management-002.idc.vipshop.com.
    idc.vip.com. 86400 IN NS gd6-conf-auto-management-001.idc.vipshop.com.
    ;ADDITIONAL       
 
    """
    domain_name = str(domain_name)
    record_type = str(record_type)
    try:
        answers = dns.resolver.query(domain_name, record_type)
        rrset = answers.rrset
        qname = answers.qname
        expiration = answers.expiration
        canonical_name = answers.canonical_name
        rdclass = answers.rdclass
        rdtype = answers.rdtype
        response = answers.response
        rcode = response.rcode()
        return rrset, qname, expiration, canonical_name, rdclass, rdtype, rcode
    except:
        print 'domain_name:', domain_name, 'is not valid'


def lookup_reserve_record(domain_ip):
    """lookup the detail reocrd by ip
    
    Args:
        String domain_ip - it's your input domain_ip etc:10.10.1.9


    Returns:
        addr - the full resever  name etc:9.1.10.10.in-addr.arpa.
        name - the full forward name etc: gd6-test-005.idc.vip.com.
        rcode - the response's rcode, success is 0
    """
    domain_ip = str(domain_ip)
    rd_type = "PTR"
    addr = reversename.from_address(domain_ip)
    try:
        answers = dns.resolver.query(addr, record_type)
        name = str(resolver.query(addr, rd_type)[0])
        response = answers.response
        rcode = response.rcode()
        return addr, name, rcode
    except:
        print 'addr', addr, 'is not valid'


def getKey(FileName):
    """get the keyRing to the key file

     ARGS:
         String: FileName

     Return:
        KeyRing
    """
    f = open(FileName)
    key = f.readline().strip('\n')
    f.close()
    k = {key.rsplit(' ')[0]:key.rsplit(' ')[6]}
    try:
        KeyRing = dns.tsigkeyring.from_text(k)
    except:
        print k, 'is not a valid key. The file should be in DNS KEY record format. See dnssec-keygen(8)'
        exit()
    return KeyRing



api.add_resource(TaskListAPI, '/', endpoint = 'list')
api.add_resource(TaskListAPI, '/add/zone_record', endpoint = 'add_dns_domain_by_domain_name')
api.add_resource(TaskAPI, '/del/zone_record', endpoint = 'del_dns_domain_by_domain_name')
api.add_resource(TaskAPI, '/update/zone_record', endpoint = 'modify_dns_domain_by_domain_name')
api.add_resource(TaskAPI, '/<string:domain_name>', endpoint = 'dns_ip_by_domain_name')
