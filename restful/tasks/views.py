# -*- coding: utf-8 -*-


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
            'domain_ip': u'10.10.1.5',
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
        update = dns.update.Update(DOMAIN, keyring=KEYRING)
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

    def get(self, id):
        task = [t for t in tasks if t['id'] == id]
        if not task:
            abort(404)
        return jsonify(task=marshal(task[0], task_fields))

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
        update = dns.update.Update(DOMAIN, keyring=KEYRING)
        update.delete(str(domain_name))
        update.add(str(domain_name), 600, 'a', str(domain_ip))
        response = dns.query.tcp(update, DNSHOST)
        return jsonify(task=marshal(task, task_fields))

    @requires_auth
    def delete(self, id):
        task = [t for t in tasks if t['id'] == id]
        if not task:
            abort(404)
        tasks.remove(task[0])
        return jsonify(result='True')


api.add_resource(TaskListAPI, '/', endpoint = 'list')
api.add_resource(TaskAPI, '/<int:id>', endpoint = 'single')
