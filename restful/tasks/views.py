# -*- coding: utf-8 -*-

import re
import socket
import sys

import dns.name
import dns.query
import dns.update
import dns.tsigkeyring

from functools import wraps

from flask import abort, Blueprint, jsonify, make_response, request
from flask.ext.restful import Api, fields, marshal, Resource, reqparse

mod = Blueprint('tasks', __name__, url_prefix='/dns/api/tasks')
api = Api(mod)

DOMAIN = 'idc.vip.com'
DNSHOST = '127.0.0.1'

KEYRING = dns.tsigkeyring.from_text({
    'update.zones.key': 'z6z4X6TZ/1zsazWf7oT1AA=='
})


tasks = [{
            'id': 1,
            'domain_name': u'gd6-test-001',
            'domain_ip': u'10.10.1.13',
            'done': False},
        {
            'id': 2,
            'domain_name': u'gd6-test-002',
            'domain_ip': u'10.10.1.6',
            'done': False}]

task_fields = {
        'id': fields.Integer, # id should be included, since fields.Url uses it.
        'domain_name': fields.String,
        'domain_ip': fields.String,
        'done': fields.Boolean,
        'uri': fields.Url('tasks.single', absolute=True)}

#dns_ip_fields = {
#        'domain_name': fields.String,
#        'ip_protocol': fields.String,
#        'domain_ip':   fields.String,
#        'uri': fields.Url('tasks.single', absolute=True)}


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
        task = {
                'id': tasks and tasks[-1]['id'] + 1 or 1,
                'domain_name': args['domain_name'],
                'domain_ip': args['domain_ip'],
                'done': False}
        tasks.append(task)
        domain_name = args['domain_name']
        domain_ip = args['domain_ip']
        print "domain_name is:  %s" % domain_name
        print "domain_ip is:  %s" % domain_ip
        print "DOMAIN is:  %s" % DOMAIN
        print "DNSHOST is:  %s" % DNSHOST
        print "KEYRING is:  %s" % KEYRING
        update = dns.update.Update(DOMAIN, keyring = KEYRING)
        update.replace(domain_name, 300, 'A', domain_ip)
        response = dns.query.tcp(update, DNSHOST, timeout=10)
        return {'task': marshal(task, task_fields)}, 201


class TaskAPI(Resource):

    def __init__(self):
        super(TaskAPI, self).__init__()
        self.parse = reqparse.RequestParser()
        self.parse.add_argument('domain_name', type=str, location='json')
        self.parse.add_argument('domain_ip', type=str, location='json')
        self.parse.add_argument('done', type=bool, location='json')

    def get(self, domain_name):
        #args = self.parse.parse_args()
        """Create a dictionary mapping address types to their IP's.
        If an error is encountered, key to error is "Error".
        """
        #task = [t for t in tasks if t['domain_name'] == domain_name]
        #if not task:
        #    abort(404)
        #domain_name = str(domain_name)
        info = []
        ip_protocol_count = 0
        #ipv6_count = 0
        try:
            for s_family, s_type, s_proto, s_cannoname, s_sockaddr in socket.getaddrinfo(domain_name, None):
                if s_family == 2 and s_type == 1:
                    ip_protocol_count += 1
                    info.append(["IPv4 (%d)" % ip_protocol_count, s_sockaddr[0]])
                if s_family == 10 and s_type == 1:
                    ip_protocol_count += 1
                    info.append(["IPv6 (%d)" % ip_protocol_count, s_sockaddr[0]])
        except socket.gaierror, err:
            info.append(["Error", "Unable to resolve %s: %s" % (domain_name, err)])

        print 'the info is: %s' % info
        #return info
        return jsonify(info=str(info), domain_name=str(domain_name))
        #return jsonify(task=marshal(task[0], dns_ip_fields))

    @requires_auth
    def put(self, id):
        task = [t for t in tasks if t['id'] == id]
        if not task:
            abort(404)
        args = self.parse.parse_args()
        task = task[0]
        for k in args:
            if args[k] is not None:
                task[k] = args[k]
        hostname = dns.name.from_text(args['domain_name'])
        print "the hostname is: %s" % hostname
        domain_name = args['domain_name']
        print "the domain_name is: %s" % domain_name
        domain_ip = args['domain_ip']
        print "the domain_ip is: %s" % domain_ip
        domain = dns.name.from_text(DOMAIN)
        print "the domain is: %s" % domain
        particle = hostname.relativize(domain)
        print "the particle is: %s" % particle
        update = dns.update.Update(DOMAIN, keyring = KEYRING)
        update.delete(str(domain_name))
        update.add(str(domain_name), 600, 'a', str(domain_ip))
        response = dns.query.tcp(update, DNSHOST)
        return jsonify(task=marshal(task, task_fields))

    @requires_auth
    def delete(self, id):
        task = [t for t in tasks if t['id'] == id]
        if not task:
            abort(404)
        args = self.parse.parse_args()
        tasks.remove(task[0])
        dns_server = str(DNSHOST)
        domain_name = args['domain_name']
        key_name = 'update.zones.key' 
        dns_update = dns.update.Update(DOMAIN, keyring = KEYRING)
        dns_update.delete(str(domain_name))
        response = send_dns_update(dns_update, dns_server, key_name)
        return jsonify(result='True')

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
api.add_resource(TaskAPI, '/<string:domain_name>', endpoint = 'dns_ip_by_domain_name')
