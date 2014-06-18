# -*- coding: utf-8 -*-

import re
import socket
import sys

import dns.name
import dns.query
import dns.update
import dns.reversename
import dns.tsigkeyring

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
        zone_name = DOMAIN
        dns_server = DNSHOST
	#rcode = add_zone_record(domain_name, domain_ip)
        rcode = create_forward_zone_record(dns_server, zone_name, record_name, record_type, record_data, ttl, key_name)

        if create_reserve: 
            record = create_reverse_zone_record(dns_server, record_data, record_name, zone_name, ttl, key_name)

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
        #return jsonify(task=marshal(task[0], dns_ip_fields))

    @requires_auth
    def put(self):
        args = self.parse.parse_args()
        domain_name = args['domain_name']
        domain_ip = args['domain_ip']
        domain = dns.name.from_text(DOMAIN)
        update = dns.update.Update(DOMAIN, keyring = KEYRING)
        update.delete(str(domain_name))
        update.add(str(domain_name), 600, 'a', str(domain_ip))
        response = dns.query.tcp(update, DNSHOST)
        #print response
        rcode = response.rcode()
        #print rcode
        if rcode == 0:
            result = 'true'
            return jsonify(domain_name = str(domain_name), domain_ip = str(domain_ip), domain = DOMAIN, dns_server = DNSHOST, result = result)
        else:
            return "update the domain_name %s to the domain_ip %s failed" % (domain_name, domain_ip)


    @requires_auth
    def delete(self):
        args = self.parse.parse_args()
        domain_name = args['domain_name']
        rcode = delete_zone_record(domain_name)
        if rcode == 0:
            result = 'true'
            return jsonify(domain_name = str(domain_name),result = result)
        else:
            return "delete the dns_domain %s failed" % domain_name


def add_zone_record(domain_name, domain_ip):
    """ add DNS zone record to dns server and return rcode.

    Args:
        domain_name host_name
        domain_ip host_ip

    Returns:
        String rcode
    """
    update = dns.update.Update(DOMAIN, keyring = KEYRING)
    update.replace(domain_name, 300, 'A', domain_ip)
    response = dns.query.tcp(update, DNSHOST, timeout=10)
    rcode = response.rcode()
    return rcode

def create_forward_zone_record(dns_server, zone_name, record_name, record_type, record_data, ttl, key_name):
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
    """
    update = dns.update.Update(zone_name, keyring = key_name)
    update.replace(record_name, ttl, record_type, record_data)
    response = dns.query.tcp(update, dns_server, timeout=10)
    rcode = response.rcode()
    return rcode

def create_reverse_zone_record(dns_server, record_data, record_name, zone_name, ttl, key_name):
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
                     ttl, key_name)
    return rcode

def delete_zone_record(domain_name):
    """ del DNS zone record from dns server and return rcode.

    Args:
        domain_name host_name

    Returns:
        String rcode
    """
    dns_server = str(DNSHOST)
    key_name = 'update.zones.key'
    dns_update = dns.update.Update(DOMAIN, keyring = KEYRING)
    dns_update.delete(str(domain_name))
    response = send_dns_update(dns_update, dns_server, key_name)
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

api.add_resource(TaskListAPI, '/', endpoint = 'list')
api.add_resource(TaskListAPI, '/add/zone_record', endpoint = 'add_dns_domain_by_domain_name')
api.add_resource(TaskAPI, '/del/zone_record', endpoint = 'del_dns_domain_by_domain_name')
api.add_resource(TaskAPI, '/update/zone_record', endpoint = 'modify_dns_domain_by_domain_name')
api.add_resource(TaskAPI, '/<string:domain_name>', endpoint = 'dns_ip_by_domain_name')
