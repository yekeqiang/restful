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

       > curl -i -H "Content-Type: application/json" -X POST -d '{"domain_name": "gd6-test-005", "domain_ip": "10.10.1.9"}' http://127.0.0.1:5000/dns/api/add/zone_record -u admin:admin


       Content-Type: application/json
       Content-Length: 143
       Server: Werkzeug/0.9.6 Python/2.7
       Date: Thu, 19 Jun 2014 03:27:49 GMT

       {   
         "dns_server": "127.0.0.1", 
         "domain": "idc.vip.com", 
         "domain_ip": "10.10.1.9", 
         "domain_name": "gd6-test-005", 
         "result": "true"
       }


-  lookup a single dns item:

   ::

       > curl -i -H "Content-Type: application/json" http://127.0.0.1:5000/dns/api/gd6-test-001

       HTTP/1.0 200 OK
       Content-Type: application/json
       Content-Length: 171
       Server: Werkzeug/0.9.6 Python/2.7
       Date: Tue, 17 Jun 2014 16:51:38 GMT

       {
         "domain_name": "gd6-test-003", 
         "info": "[['IPv4 (1)', '10.10.1.7']]"
       }
-  update a dns item:

   ::

       > curl -i -H "Content-Type: application/json" -X PUT -d '{"domain_name": "gd6-test-006", "domain_ip": "10.10.1.12"}' http://127.0.0.1:5000/dns/api/update/zone_record -u admin:admin 

       Content-Type: application/json
       Content-Length: 144
       Server: Werkzeug/0.9.6 Python/2.7
       Date: Thu, 19 Jun 2014 03:25:45 GMT

       {
         "dns_server": "127.0.0.1", 
         "domain": "idc.vip.com", 
         "domain_ip": "10.10.1.13", 
         "domain_name": "gd6-test-006", 
         "result": "true"
       }

-  delete a dns item:

   ::

       > curl -i -H "Content-Type: application/json" -X DELETE -d '{"domain_name": "gd6-test-005"}' http://127.0.0.1:5000/dns/api/del/zone_record -u  admin:admin 

       HTTP/1.0 200 OK
       Content-Type: application/json
       Content-Length: 22
       Server: Werkzeug/0.9.6 Python/2.7
       Date: Thu, 19 Jun 2014 03:30:21 GMT

       {
         "domain_name": "gd6-test-005", 
         "result": "true"
       }
