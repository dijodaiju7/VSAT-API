from fastapi import FastAPI,Header, HTTPException
import pandas as pd
import ssl
import requests
import time
import dns.resolver
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup as bs
import socket
import json
import whois
from requests_html import HTMLSession
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from supabase import create_client, Client
import os
import re
from typing import Optional
wd=""
API_URL = 'https://mohcxviiclxxhwbvdzog.supabase.co'
API_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im1vaGN4dmlpY2x4eGh3YnZkem9nIiwicm9sZSI6ImFub24iLCJpYXQiOjE2NzU5MTM5ODgsImV4cCI6MTk5MTQ4OTk4OH0.ahfdv9QG5Pdi2qWh4n4CJ3wMfZiE0bYhWkH_6Fkj2d8'
app=FastAPI( title="VSAT API",
    description="VSAT API is built with FastAPI to perform various security scans and return the output 🚀",
    version="1.0.0",)
async def authenticate_api_key(api_key):
    supabase= create_client(API_URL,API_KEY)
    response = supabase.table('api').select("token","domain").execute()
    df = pd.DataFrame(response.data)
    #print(df)
    #print(response)
    ind=len(df.index)
    tokenval=df['token']
    domainval=df['domain']
    #inittok=tokenval[0]
    #print(inittok)
    #initdomain=domainval[0]
    flag=False
    global wd
    for i in range(0,ind):
        if tokenval[i] == api_key:
            flag=True
            wd=domainval[i]
    if flag==False:
        #raise HTTPException(status_code=200, detail="Valid API key")
    #else:
        raise HTTPException(status_code=401, detail="Invalid API key")
        
@app.get("/")
async def home(api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    await authenticate_api_key(api_key)

    return{"Welcome to VSAT API. Visit /docs for the API documentation"}
@app.get("/hostname",summary="Returns the ip address for the hostname")
async def get_hostname_info(api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    await authenticate_api_key(api_key)
    try:
        socket.gethostbyname(wd)
        a=socket.gethostbyname(wd)
        return{"Valid hostname": a}
    except:
        return{"Invalid hostname": wd}
    

@app.get("/sslinfo",summary="Returns the SSL information of your domain")    
async def get_ssl_info(api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    with socket.create_connection((wd, 443)) as sock:
        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=wd) as ssock:
            cert = ssock.getpeercert()
        return(cert)
@app.get("/dnsinfo",summary="Lists the DNS records of your domain")        
async def get_dns_records_info(api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    await authenticate_api_key(api_key)
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
async def get_hsts(api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    await authenticate_api_key(api_key)
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
async def get_url_redirection(api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    await authenticate_api_key(api_key)
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
async def get_webpage_speed(api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    await authenticate_api_key(api_key)
    start = time.time()
    response = requests.get('https://'+wd)
    end = time.time()
    elapsed_time = end - start
    return{"Time elapsed": elapsed_time}

@app.get('/whoislookup')
async def get_whois_info(api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    await authenticate_api_key(api_key)
    wdict={}
    try:
        w = whois.whois(wd)
        wdict.update({'Whois info':w})
    except Exception as e:
        wdict.update({'Error getting WHOIS':wd})
    return (wdict)
@app.get("/safeweb")
async def get_safeweb(api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    await authenticate_api_key(api_key)
    chrome_options = Options()

    chrome_options.add_argument("--headless")

    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")

    url = "https://safeweb.norton.com/"
    driver = webdriver.Chrome(options=chrome_options)
    driver.get(url)

    webcheck = wd
    e1 = driver.find_element(By.ID, 'appendedInputButton').send_keys(webcheck)
    submit = driver.find_element(By.ID, 'homeSearchImg')

    submit.click()
    time.sleep(5)

    result = driver.find_element(
        By.XPATH, '//*[@id="bodyContent"]/div/div/div[3]/div[1]/div[1]/div[2]/div[1]/div/b')

    return (result.text)
@app.get("/phishtank")
async def get_phishtank(api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    await authenticate_api_key(api_key)
    pdict = {}
    chrome_options = Options()

    chrome_options.add_argument("--headless")

    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")

    url = "https://phishtank.org/"
    driver = webdriver.Chrome(options=chrome_options)
    driver.get(url)

    domain = wd
    e1 = driver.find_element(By.NAME, 'isaphishurl').clear()

    e3 = driver.find_element(By.NAME, 'isaphishurl').send_keys(domain)
    submit = driver.find_element(
        By.XPATH, '//*[@id="maincol"]/div/div[2]/form/p/input[2]')
    submit.click()
    time.sleep(3)

    try:
        submit = driver.find_element(
            By.XPATH, '//*[@id="history"]/table[1]/tbody/tr/td[2]/h3/b')
        pdict.update({"Site details": submit.text})
        if submit.text == "":
            submit = driver.find_element(By.XPATH, '//*[@id="widecol"]/div/h3')
            pdict.update({"Site details": submit.text})

    except:
        submit = driver.find_element(
            By.XPATH, '//*[@id="maincol"]/div/div[2]/form/p/b/tt')
        pdict.update({"No phishing info about": submit.text})
    return (pdict)
@app.get("/xssbasic")
async def get_xssbasic(api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    await authenticate_api_key(api_key)
    xdict = {}
    url = "https://"+wd

# Step 1: Find all the forms in the page
    soup = bs(requests.get(url).content, "html.parser")
    forms = soup.find_all("form")
    xdict.update({"Number of forms detected": len(forms)})

    # Step 2: Try submitting a payload to each form and check for XSS vulnerability
    js_script = "<script>alert(XSS)</script>"
    for form in forms:
        # Extract form details
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = []
        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            inputs.append({"type": input_type, "name": input_name})
        form_details = {"action": action, "method": method, "inputs": inputs}

        # Submit payload to form
        target_url = urljoin(url, action)
        data = {}
        for input in inputs:
            if input["type"] == "text" or input["type"] == "search":
                input["value"] = js_script
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value
        if method == "post":
            res = requests.post(target_url, data=data)
        else:
            res = requests.get(target_url, params=data)

        # Check for XSS vulnerability
        content = res.content.decode()
        if js_script in content:
            xdict.update({"XSS Detected": form_details})
        else:
            xdict.update({"XSS not detected on": url})
    return (xdict)
@app.get("/webtechscan")
async def get_webtech(api_key: Optional[str] = Header(None, alias="X-API-KEY")):
    await authenticate_api_key(api_key)
    webdict={}
    url = "https://"+wd
    try:
        response = requests.get(url)
        
        server = response.headers.get('server')
        if server:
            webdict.update({"Server": server})
        
        technologies = []
        content = response.text.lower()
        if 'x-powered-by' in response.headers:
            technologies.extend(re.findall('[\w-]+', response.headers['X-Powered-By']))
        if 'x-aspnet-version' in response.headers:
            technologies.append('ASP.NET')
        if 'x-drupal-cache' in response.headers:
            technologies.append('Drupal')
        if 'x-generator' in response.headers:
            technologies.extend(re.findall('[\w-]+', response.headers['X-Generator']))
        if 'react' in content:
            technologies.append('React')
        if 'django' in content:
            technologies.append('Django')
        if 'next/static' in content:
            technologies.append('Next.js')
        if 'astro' in content:
            technologies.append('Astro')
        if 'wp-' in content:
            technologies.append('Wordpress')
        if 'bootstrap' in content:
            technologies.append('Bootstrap')
        if 'php' in content:
            technologies.append('PHP')
        if 'jsp' in content:
            technologies.append('JSP')
        if 'webpack' in content:
            technologies.append('Webpack')
        if 'ghost/' in content:
            technologies.append('Ghost')
        if 'django' in response.text.lower():
            technologies.append('Django')
        if 'laravel' in response.text.lower():
            technologies.append('Laravel')
        if 'rails' in response.text.lower():
            technologies.append('Ruby on Rails')
        if 'spring' in response.text.lower():
            technologies.append('Spring')
        if 'symfony' in response.text.lower():
            technologies.append('Symfony')
        if 'express' in response.text.lower():
            technologies.append('Express.js')
        if 'sites.google.com' in response.text.lower():
            technologies.append('Google Sites')

        # Look for JavaScript libraries
        if 'jquery' in response.text.lower():
            technologies.append('jQuery')
        if 'react' in response.text.lower():
            technologies.append('React')
        if 'vue' in response.text.lower():
            technologies.append('Vue.js')
        if 'angular' in response.text.lower():
            technologies.append('Angular')

        # Look for CSS frameworks
        if 'bootstrap' in response.text.lower():
            technologies.append('Bootstrap')
        if 'foundation' in response.text.lower():
            technologies.append('Foundation')

        # Look for CMS platforms
        if 'wordpress' in response.text.lower():
            technologies.append('WordPress')
        if 'joomla' in response.text.lower():
            technologies.append('Joomla!')
        if 'drupal' in response.text.lower():
            technologies.append('Drupal')

        # Look for e-commerce platforms
        if 'magento' in response.text.lower():
            technologies.append('Magento')
        if 'shopify' in response.text.lower():
            technologies.append('Shopify')

        # Look for web servers
        if 'nginx' in response.headers.get('server', '').lower():
            technologies.append('nginx')
        if 'apache' in response.headers.get('server', '').lower():
            technologies.append('Apache')
        
        if technologies:
            webdict.update({"Technologies":technologies})
        else:
            webdict.update({"Info":"No technologies found."})
    except:
        webdict.update({"Info":"An error occurred while trying to fetch the website."})
    return (webdict)

