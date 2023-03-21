from fastapi import FastAPI
import ssl
import requests
import time
import dns.resolver
import socket
import json
import whois
from requests_html import HTMLSession
from bs4 import BeautifulSoup
wd="rajagiritech.ac.in"
app=FastAPI( title="VSAT API",
    description="VSAT API is built with FastAPI to perform various security scans and return the output 🚀",
    version="1.0.0",)
@app.get("/")
async def home():
    return{"Welcome to VSAT API. Visit /docs for the API documentation"}
@app.get("/hostname",summary="Returns the ip address for the hostname")
async def get_hostname_info():
    try:
        socket.gethostbyname(wd)
        a=socket.gethostbyname(wd)
        return{"Valid hostname": a}
    except:
        return{"Invalid hostname": wd}
    

@app.get("/sslinfo",summary="Returns the SSL information of your domain")    
async def get_ssl_info():
    with socket.create_connection((wd, 443)) as sock:
        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=wd) as ssock:
            cert = ssock.getpeercert()
        return(cert)
@app.get("/dnsinfo",summary="Lists the DNS records of your domain")        
async def get_dns_records_info():
    dnsd={}
    ids = [
        'NONE',
        'A',
        'NS',
        'MD',
        'MF',
        'CNAME',
        'SOA',
        'MB',
        'MG',
        'MR',
        'NULL',
        'WKS',
        'PTR',
        'HINFO',
        'MINFO',
        'MX',
        'TXT',
        'RP',
        'AFSDB',
        'X25',
        'ISDN',
        'RT',
        'NSAP',
        'NSAP-PTR',
        'SIG',
        'KEY',
        'PX',
        'GPOS',
        'AAAA',
        'LOC',
        'NXT',
        'SRV',
        'NAPTR',
        'KX',
        'CERT',
        'A6',
        'DNAME',
        'OPT',
        'APL',
        'DS',
        'SSHFP',
        'IPSECKEY',
        'RRSIG',
        'NSEC',
        'DNSKEY',
        'DHCID',
        'NSEC3',
        'NSEC3PARAM',
        'TLSA',
        'HIP',
        'CDS',
        'CDNSKEY',
        'CSYNC',
        'SPF',
        'UNSPEC',
        'EUI48',
        'EUI64',
        'TKEY',
        'TSIG',
        'IXFR',
        'AXFR',
        'MAILB',
        'MAILA',
        'ANY',
        'URI',
        'CAA',
        'TA',
        'DLV',
    ]
    
    for a in ids:
        try:
            answers = dns.resolver.resolve(wd, a)
            for rdata in answers:
                #print(a, ':', rdata.to_text())
                dnsd[a]=rdata.to_text()
            time.sleep(10)
        except Exception as e:
            pass  # or pass
    return(dnsd)

# -------Web security scans----------

@app.get("/httpsecheader")
async def get_hsts():
    ur='https://'+wd
    hsd={}
    response = requests.get(ur)
    headers = response.headers
    cookies = response.cookies

# XXSS block
    try:
        if headers["X-XSS-Protection"]:
            hsd.update({'X-XSS-Protection' :  'pass'})
    except KeyError:
        hsd.update({'X-XSS-Protection header not present' :  'fail!'})

# NOSNIFF block
    try:
     if headers["X-Content-Type-Options"].lower() == "nosniff":
        hsd.update({'X-Content-Type-Options' :  'pass'})
     else:
         hsd.update({'X-Content-Type-Options header not set correctly' :  'fail!'})
    except KeyError:
        hsd.update({'X-Content-Type-Options header not present' :  'fail!'})

# XFrame block
    try:
        if "deny" in headers["X-Frame-Options"].lower():
           hsd.update({'X-Frame-Options' :  'pass'})
        elif "sameorigin" in headers["X-Frame-Options"].lower():
            hsd.update({'X-Frame-Options' :  'pass'})
        else:
            hsd.update({'X-Frame-Options header not set correctly' :  'fail!'})
    except KeyError:
        hsd.update({'X-Frame-Options header not present' :  'fail!'})

# HSTS block
    try:
     if headers["Strict-Transport-Security"]:
       hsd.update({'Strict-Transport-Security' :  'pass'})
    except KeyError:
        hsd.update({'Strict-Transport-Security header not present' :  'fail!'})

# Policy block
    try:
        if headers["Content-Security-Policy"]:
            hsd.update({'Content-Security-Policy' :  'pass'})
    except KeyError:
        hsd.update({'Content-Security-Policy header not present' :  'fail!'})

# Cookie blocks
    for cookie in cookies:
        hsd.update({'Set-Cookie' :  ''})
        if cookie.secure:
            hsd.update({'Secure' :  'pass'})
        else:
            hsd.update({'Secure attribute not set' :  'fail!'})
        if cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly'):
            hsd.update({'HttpOnly' :  'pass'})
        else:
             hsd.update({'HttpOnly attribute not set' :  'fail!'})
    return(hsd)
@app.get("/urlredirection")
async def get_url_redirection():
    links = []
    session = HTMLSession()
    ur='https://'+wd
    response = session.get(ur)
    soup = BeautifulSoup(response.text,'lxml')
    for link in soup.find_all('a',href=True):
        if(link['href'].startswith('./')):
            link['href'] = (ur) + link['href']
        if(link['href'].startswith('/')):
            link['href'] = ur + link['href']
        if(link['href'].startswith('#')):
            continue
        if(link['href'].startswith('http')):
            links.append(link['href'])
        i=0
        for link in links:
            print(link)
    return(links)

@app.get("/wepagespeed")
async def get_webpage_speed():
    start = time.time()
    response = requests.get('https://'+wd)
    end = time.time()
    elapsed_time = end - start
    return{"Time elapsed": elapsed_time}

@app.get('/whoislookup')
async def get_whois_info():
    wdict={}
    try:
        w = whois.whois(wd)
        wdict.update({'Whois info':w})
    except Exception as e:
        wdict.update({'Error getting WHOIS':wd})
    return (wdict)
