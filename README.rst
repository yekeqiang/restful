RESTful
=======

A dns RESTful sample with Flask.

-  get dns list:

   ::

       > curl -i -H "Content-Type: application/json" http://127.0.0.1:5000/dns/api/tasks/

       HTTP/1.0 200 OK
       Content-Type: application/json
       Content-Length: 370
       Server: Werkzeug/0.9.6 Python/2.7
       Date: Tue, 17 Jun 2014 16:44:59 GMT

       {
          "tasks": [
           {
           "domain_ip": "10.10.1.5", 
           "domain_name": "gd6-test-001", 
           "done": false, 
           "id": 1, 
           "uri": "http://127.0.0.1:5000/dns/api/tasks/1"
           }, 
           {
           "domain_ip": "10.10.1.6", 
           "domain_name": "gd6-test-002", 
           "done": false, 
           "id": 2, 
           "uri": "http://127.0.0.1:5000/dns/api/tasks/2"
           }
           ]
       }
-  create a dns item:

   ::

       > curl -i -H "Content-Type: application/json" -X POST -d '{"domain_name": "gd6-test-007", "domain_ip": "10.10.1.12"}' http://127.0.0.1:5000/dns/api/tasks/ -u admin:admin 
       HTTP/1.0 201 CREATED
       Content-Type: application/json
       Content-Length: 197
       Server: Werkzeug/0.9.6 Python/2.7
       Date: Tue, 17 Jun 2014 16:47:02 GMT

       {
         "task": {
         "domain_ip": "10.10.1.12", 
         "domain_name": "gd6-test-007", 
         "done": false, 
         "id": 3, 
         "uri": "http://127.0.0.1:5000/dns/api/tasks/3"
         }    
       }

-  lookup a single dns item:

   ::

       > curl -i -H "Content-Type: application/json" http://127.0.0.1:5000/dns/api/tasks/1

       HTTP/1.0 200 OK
       Content-Type: application/json
       Content-Length: 171
       Server: Werkzeug/0.9.6 Python/2.7
       Date: Tue, 17 Jun 2014 16:51:38 GMT

       {
         "task": {
         "domain_ip": "10.10.1.5", 
         "domain_name": "gd6-test-001", 
         "done": false, 
         "id": 1, 
         "uri": "http://127.0.0.1:5000/dns/api/tasks/1"
         }
       }
-  update a dns item:

   ::

       > curl -i -H "Content-Type: application/json" -X PUT -d '{"domain_name": "gd6-test-001", "domain_ip": "10.10.1.13"}' http://127.0.0.1:5000/dns/api/tasks/3 -u admin:admin

       HTTP/1.0 200 OK
       Content-Type: application/json
       Content-Length: 172
       Server: Werkzeug/0.9.6 Python/2.7
       Date: Tue, 17 Jun 2014 16:55:43 GMT

       {
         "task": {
         "domain_ip": "10.10.1.13", 
         "domain_name": "gd6-test-001", 
         "done": false, 
         "id": 3, 
         "uri": "http://127.0.0.1:5000/dns/api/tasks/3"
         }
       }
-  delete a dns item:

   ::

       > curl -i -H "Content-Type: application/json" -X DELETE  http://127.0.0.1:5000/dns/api/tasks/1 -u  admin:admin

       HTTP/1.0 200 OK
       Content-Type: application/json
       Content-Length: 22
       Server: Werkzeug/0.9.6 Python/2.7
       Date: Tue, 17 Jun 2014 16:57:43 GMT

       {    
         "result": "True"
       }

