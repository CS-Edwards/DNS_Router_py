'''
Simple Authoritative DNS Server
Based on project spec ICS651- Comp Networks
@author: CS Edwards
'''
import socket, glob, json
from sys import byteorder

##read in commands from main per project spec

port=12345 #will set to port to user input per assignment
ip='127.0.0.1' 

#socket IPv4 UDP
s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
s.bind((ip,port))

def zones():
    
    jsonzone={}
    
    zfile=glob.glob('zones/*.zone')
    print(zfile)
    
    for zone in zfile:
        with open(zone) as zonedata:
            zname = data["$origin"]
            data=json.load(zonedata)
            jsonzone[zname]=data
    
    return jsonzone

zonedata = zones();


def getflags(flags):
    
    byte1= bytes(flags[:1])
    #byte2= bytes(flags[1:2])
    
    
    rflags='' #response flags
    QR = '1'
    
    OPCODE=''
    for bit in range(1,5):
        #print(bit)
        OPCODE += str(ord(byte1)&(1<<bit)) #convert byte 1 from byte to in, bit shift (check each bit) and convert to string
    
    AA = '1'
    TC ='0'
    RD='0' #simple dns does not support recursion
    RA = '0'#simple dns does not support recursion
    Z='000'  
    RCODE= '0000'
    
    return int(QR+OPCODE+AA+TC+RD,2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE,2).to_bytes(1, byteorder='big')

def getdomain(data):
    print(data)
    
    s=0
    length=0
    domain=''
    domainarr=[]
    x=0
    y=0
    
    for byte in data:
        if s==1:
            if byte !=0:
                domain+=chr(byte)
            x+=1
            if x== length:
                domainarr.append(domain)
                domain=''
                s=0
                x=0
            if byte == 0:
                domainarr.append(domain)
                break
        else:
            s=1;
            length=byte
    
        print(domain)
    
    
    y+=1
    
    qtype = data[y:y+2]
    print(qtype)
    
    return(domainarr,qtype)

def getzone(domain):
    global zonedata
    z_name = '.'.join(domain)
    return zonedata[z_name]

def getrecords(data):
    domain,qtype = getdomain(data) 
    qt=''
    if qtype == b'\x00\x01':
        qt='A'
    
    #if qtype == b'\x' #28 AAAA for IPv6
    
    zone=getzone(domain)
    
    return(zone[qt],qt,domain)

def buildresponse(data):
    TID =data[0:2] #transaction ID from header
   
    
    #Flags
    Flags = getflags(data[2:4])
    print(Flags)
    
    #Question Count
    QDCOUNT = b'\x00\x01'
    
    #Answer Count
    
    #print(getrecords(data[12:]))#start after 12 byte header
    ANCOUNT = len(getrecords(data[12:])[0]).to_bytes(2, byteorder='big')
    print(ANCOUNT)
    
    #Name Server Count
    NSCOUNT = (0).to_bytes(2,byteorder='big')
    
    #Additional Count
    ARCOUNT = (0).to_bytes(2,byteorder='big')
    
    dnsheader = TID+Flags+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT
    #print(dnsheader)
    
    dnsbody=b''
    
    records,rectype,domainname = getrecords(data[12:])
    
    ###dnsQuestion### TODO-- build question
    

while 1:
    data,addr = s.recvfrom(512) #512 buffer size RFC 1035
    print(data)
    r = buildresponse(data)
    #s.sendto(b'Hello World',addr) #test in dig
    
    s.sendto(r,addr)


