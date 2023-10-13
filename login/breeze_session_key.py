'''
:Special Thanks to the person who gave me access to his trading account to prepare the code 
:description: Code to automate login in icici breeze
:author: Tapan Hazarika
:license: MIT
'''
__author__ = "____Tapan Hazarika____"

import os
import rsa
import yaml
import json
import pyotp
import httpx
import logging
import asyncio
import requests
import binascii
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import quote

#logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
#logging.basicConfig(level=logging.DEBUG)

class BreezeLogin:
    __config = {
        "base_url" : "https://api.icicidirect.com/apiuser",
        "api_base" : "https://api.icicidirect.com/breezeapi/api/v1",
        "routes" : {
            "login" : "/login?api_key={}",
            "trade" : "/tradelogin",
            "getotp" : "/tradelogin/getotp",
            "validate" : "/tradelogin/validateuser",
            "customerdetails" : "/customerdetails",
        },
        "headers" : {
                "Content-Type": "application/json",
            },
    }

    def __init__(self):
        with open('cred.yml') as f:
            cred = yaml.load(f, Loader=yaml.FullLoader)

        self.user = cred["USER"]
        self.password = cred["PWD"]
        self.totp = cred["TOTP_KEY"]
        self.apikey = cred["API_KEY"]
        self.apisecret = cred["API_SECRET"]
        self.session_config =  os.path.join(os.path.dirname(__file__), 'login_config.json') 
        self.current_date = datetime.now().strftime("%d-%m-%Y")

        self.client = httpx.AsyncClient()

    def encode(self, key, value):
        exponent, modulus = key.split("~")

        publickey = rsa.PublicKey(int(modulus, 16), int(exponent, 16))
        encrypted_key = rsa.encrypt(message = value.encode('utf-8'), pub_key=publickey)
        encrypted_hex = binascii.hexlify(encrypted_key).decode('utf-8')
        self.hidp = encrypted_hex
        logging.info("hidp : {}".format(self.hidp))
    
    async def fetch_api_session(self):
        try:
            response = await self.client.post(
                                url = f'{self.__config["base_url"]}{self.__config["routes"]["login"]}'.format(quote(self.apikey))
                            )
            response.raise_for_status()
            logging.debug("SessionLogin : {}".format(response.text))

            if response.status_code == 200:
                res_cookies = response.cookies
                cookies = {
                    "AlteonAPI" : res_cookies.get("AlteonAPI"),
                    "nginx_srv_id" : res_cookies.get("nginx_srv_id")
                    } 

                soup = BeautifulSoup(response.content, 'html.parser')
                form = soup.find('form', {'name': 'frmLog'})

                if form:
                    app_key = form.find('input', {'name': 'AppKey'})['value']
                    time_stamp = form.find('input', {'name': 'time_stamp'})['value']
                    checksum = form.find('input', {'name': 'checksum'})['value']

                logging.info('AppKey: {}'.format(app_key))
                logging.info('time_stamp: {}'.format(time_stamp))
                logging.info('checksum: {}'.format(checksum))

                response = await self.client.post(
                                  url = f'{self.__config["base_url"]}{self.__config["routes"]["trade"]}',
                                  cookies = cookies,
                                  data = {
                                    "AppKey": app_key,
                                    "time_stamp": time_stamp,
                                    "checksum": checksum,
                                  }
                                )
                response.raise_for_status()
                logging.debug("Tradelogin : {}".format(response.text))

                if response.status_code == 200:
                    cookies.update(
                        {
                            "ASP.NET_SessionId" : response.cookies.get("ASP.NET_SessionId")
                        }
                    )

                    soup = BeautifulSoup(response.content, 'html.parser')
                    login_form = soup.find('div', class_='form-group pb-2 text-center')

                    if login_form:
                        btnsubmit = login_form.find('input', {'id': 'btnSubmit'})['value']
                        hidplk = login_form.find('input', {'id': 'hidplk'})['value']
                        hidenc = login_form.find('input', {'id': 'hidenc'})['value']
                        hidslk = login_form.find('input', {'id': 'hidslk'})['value']
                        hidredurl = login_form.find('input', {'id': 'hidredurl'})['value']

                    logging.info("btnsubmit: {}".format(btnsubmit) )
                    logging.info("hidplk: {}".format(hidplk))
                    logging.info("hidenc: {}".format(hidenc))
                    logging.info("hidslk: {}".format(hidslk))
                    logging.info("hidredurl: {}".format(hidredurl))

                    self.encode(key = hidenc, value = self.password)

                    data = {
                        "txtuid" : self.user,
                        "txtPass" : "************",
                        "hidp" : self.hidp,
                        "chkssTnc" : "Y",
                        "btnSubmit" : btnsubmit,
                        "hidenc" : hidenc,
                        "hidplk" : hidplk,
                        "hidredurl" : hidredurl,
                        "hidslk" : hidslk,
                        "hidPATH" : "",
                        "hidPARAM" : "",
                        "hidpaths" : "",
                        "hidparams" : "",
                        "hiddob" : ""
                    } 

                    response = await self.client.post(
                                        url = f'{self.__config["base_url"]}{self.__config["routes"]["getotp"]}',  
                                        cookies = cookies,
                                        data = data
                                    )
                    response.raise_for_status()
                    logging.debug("Getotp : {}".format(response.text))

                    if response.status_code == 200:
                        soup = BeautifulSoup(response.content, 'html.parser')

                        button1 = soup.find('input', {'id': 'Button1'})['value']
                        hitk = soup.find('input', {'id': 'hitk'})['value']
                        udid = soup.find('input', {'id': 'udid'})['value']
                        hidsd = soup.find('input', {'id': 'hidsd'})['value']
                        hiistotp = soup.find('input', {'id': 'hiistotp'})['value']
                        hiforotp = soup.find('input', {'id': 'hiforotp'})['value']

                        logging.info("Button1: {}".format(button1))
                        logging.info("hitk: {}".format(hitk))
                        logging.info("udid: {}".format(udid))
                        logging.info("hidsd: {}".format(hidsd))
                        logging.info("hiistotp: {}".format(hiistotp))
                        logging.info("hiforotp: {}".format(hiforotp))

                        otp_data = {
                                "hiotp" : "",
                                "Button1" : button1,
                                "hitk" : hitk,
                                "udid" : udid,
                                "hidsd" : hidsd,
                                "hiistotp" : hiistotp,
                                "hiforotp" : hiforotp 
                            }

                        data.update(otp_data)

                        response = await self.client.post(
                                        url = f'{self.__config["base_url"]}{self.__config["routes"]["validate"]}',  
                                        cookies = cookies,
                                        data = {
                                            **data, 
                                            "hiotp": pyotp.TOTP(self.totp).now()
                                            }
                                        )
                        response.raise_for_status()
                        logging.debug("Validate : {}".format(response.text))

                        if response.status_code == 200:
                            soup = BeautifulSoup(response.content, 'html.parser')

                            api_session = soup.find('input', {'id': 'API_Session'})['value']

                            logging.info("API_Session: {}".format(api_session))

                            return api_session
        except(Exception, httpx.RequestError) as e:
            logging.debug("Session Token Error : {}".format(e))
    
    async def fetch_session_token(self):

        try:
            api_session = await self.fetch_api_session()
            body = {
                "SessionToken": api_session,
                "AppKey": self.apikey,
            }
            body = json.dumps(body, separators=(',', ':'))
            response = requests.get(
                url=  f'{self.__config["api_base"]}{self.__config["routes"]["customerdetails"]}',
                data = body,
                headers = self.__config["headers"]  
                )
            response.raise_for_status()
            logging.debug("Customer_Details : {}".format(response.text))
            if response:
                session_token = response.json().get("Success", {}).get("session_token", '')
                logging.info("Session Token : {}".format(session_token))
                return session_token
        except(Exception, requests.exceptions.RequestException) as e:
            logging.debug("Session Token Error : {}".format(e))
    
    def manage_session_data(self, data=None, operation="w"):
        with open(self.session_config, operation) as json_file:
            if operation == "w":
                json.dump(
                    data, 
                    json_file,
                    indent= 4
                )
            else:
                login_data = json.load(json_file)
                return login_data
    
    def get_api_session(self):
        session_token = asyncio.run(self.fetch_api_session())
        return session_token
    
    def get_session_token(self):
        session_token = asyncio.run(self.fetch_session_token())
        return session_token
    
    def get_session_data(self):
        self.token = self.get_session_token()
        data = {
            "date" : self.current_date,
            "api_secret" : self.apisecret,
            "token" : self.token,
        }
        return data
    
    def check_session_token(self, hard_refresh= False):
        if hard_refresh:
            session_data = self.get_session_data()
            self.manage_session_data(data = session_data)
            return self.apisecret, self.token
        
        if os.path.exists(self.session_config):
            session_data = self.manage_session_data(operation= "r")
            if session_data["date"] == self.current_date:
                return session_data["api_secret"], session_data["token"]
            else:
                session_data = self.get_session_data()
                self.manage_session_data(data = session_data)
                return self.apisecret, self.token
        else:
            session_data = self.get_session_data()
            self.manage_session_data(data = session_data)
            return self.apisecret, self.token
        
if __name__ == "__main__":
    bz = BreezeLogin()

    # If need only api_session key then only run

    #api_session = bz.get_api_session()
    #print(api_session)

    # If need session_token without saving to json file to use in breezeconnect generate_session then run

    #session_token = bz.get_session_token()
    #print(f"SESSION_TOKEN : {session_token}") 

    # It will load session token from saved file if the token is saved within same date
    # or fetch it from breeze api . if token is not working (expired) within same day  
    # because of logged out or any other reason use this with hard_refresh = True

    api_secret, session_token = bz.check_session_token()
    print(f"API_SECRET : {api_secret} , SESSION_TOKEN : {session_token}") 


     












