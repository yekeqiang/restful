import dns.reversename
import dns.resolver
import dns.name

def genPTR(Address):
    try:
        a = dns.reversename.from_address(Address)
    except:
        print 'Error:', Address, 'is not a valid IP adresss'
    return a

def parseName(Origin, Name):
    try:
        n = dns.name.from_text(Name)
        print 'the n is: %s' % n
    except:
        print 'Error:',  n, 'is not a valid name'
        exit()
    if Origin is None:
        Origin = dns.resolver.zone_for_name(n)
        print 'the Origin re is: %s' % Origin
        Name = n.relativize(Origin)
        print 'the Name re is: %s' % Name
        return Origin, Name
    else:
        try:
            Origin = dns.name.from_text(Origin)
            print 'the Origin is: %s' % Origin
        except:
            print 'Error:',  Name, 'is not a valid origin'
            exit()
        Name = n - Origin
        print "Name is %s" % Name
        return Origin, Name

address = '10.10.1.10'
addr = genPTR(address)
ot = genPTR(address).to_text()
print "ot %s" % ot
print addr
name = 'gd6-test-009'
Origin = None
Origin, Name = parseName(Origin, genPTR(address).to_text())
ptrTarget = Name.to_text() + '.' + Origin.to_text()
print Origin, Name
print ptrTarget
