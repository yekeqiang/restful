import dns.tsigkeyring
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

keyFile = "/var/named/chroot/etc/Kupdate.zones.key.+157+30577.key"
getKey(keyFile)
