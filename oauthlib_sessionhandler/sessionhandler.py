from oauthlib.oauth2 import Client, LegacyApplicationClient, BackendApplicationClient
# from oauthlib.oauth2 import InvalidGrantError
from requests_oauthlib import OAuth2Session
import requests
import logging
import time
import urllib.parse

class OAuthLibSessionHandler():
    def __init__(self, 
                 wellknown_url : str = None,
                 token_url : str = None,
                 
                 client_id : str = None,

                 username : str = None,
                 password : str = None,

                 oidc_userinfo_url : str = None,
                 oidc_end_session_url : str = None,

                 ) -> None:
        
        self.wellknown_url = self.__set_ifnotnone_or_empty(wellknown_url)
        self.token_url = self.__set_ifnotnone_or_empty(token_url)
        
        self.client_id = client_id
        self.username = username
        self.password = password
        
        self.oidc_userinfo_url = self.__set_ifnotnone_or_empty(oidc_userinfo_url)
        self.oidc_end_session_url = self.__set_ifnotnone_or_empty(oidc_end_session_url)

        # some detailed config not available in constructor
        # TODO doc config params
        # TODO make accessible from outside in convenient way
        self.__premature_refresh_time_seconds = 30
        self.__include_clientid_in_refreshrequest = True

        self.logger = logging.getLogger(__name__)
        self.logger.debug("initalized")

        self.client = LegacyApplicationClient(client_id=self.client_id)
        self.session = OAuth2Session(client=self.client)

    @staticmethod
    def __set_ifnotnone_or_empty(input : str) -> str:
        retval = None
        if input is not None and len(input) > 0:
            retval = input

        return retval

    def _parse_wellknown_oidc_configuration(self) -> bool:
        success = True
        
        try:
            with requests.get(self.wellknown_url) as response:
                data = response.json()
        
                if 'token_endpoint' in data:
                    if self.token_url is None:
                        self.token_url = data["token_endpoint"]

                if 'userinfo_endpoint' in data:
                    if self.oidc_userinfo_url is None:
                        self.oidc_userinfo_url = data["userinfo_endpoint"]

                if 'end_session_endpoint' in data:
                    if self.oidc_end_session_url is None:
                        self.oidc_end_session_url = data["end_session_endpoint"]

        except Exception as e:
            self.logger.error(f"{type(e).__name__} while retrieving wellknown oidc_configuration")
            self.logger.debug("exec_info", exc_info=True)
            success = False

        return success
    
    def _get_token_url(self) -> str:
        if self.token_url is None:
            self._parse_wellknown_oidc_configuration()
        
        return self.token_url

    def _get_oidc_userinfo_url(self) -> str:
        if self.oidc_userinfo_url is None:
            self._parse_wellknown_oidc_configuration()
        
        return self.oidc_userinfo_url
    
    def _get_oidc_end_session_url(self) -> str:
        if self.oidc_end_session_url is None:
            self._parse_wellknown_oidc_configuration()
        
        return self.oidc_end_session_url
        
    def _refresh_token(self) -> bool:
        if 'refresh_token' not in self.client.token:
            self.logger.error("no refresh token available")
            return False
        
        body = {}
        if self.__include_clientid_in_refreshrequest:
            body['client_id'] = self.client_id

        try:
            self.session.refresh_token(
                self._get_token_url(),
                refresh_token=self.client.token['refresh_token'],
                body=urllib.parse.urlencode(body),
            )
        
        except Exception as e:
            self.logger.error(f"{type(e).__name__} while refreshing token")
            self.logger.debug("exec_info", exc_info=True)
            return False
        
        return True
    
    def _fetch_token(self) -> bool:
        try:
            self.session.fetch_token(
                token_url=self._get_token_url(), 
                username=self.username, 
                password=self.password
            )

        except Exception as e:
            self.logger.error(f"{type(e).__name__} while fetching token, message: {str(e)}")
            self.logger.debug("exec_info", exc_info=True)
            return False
        
        return True
    
    def get_oidc_userinfo(self) -> dict:
        if self._get_oidc_userinfo_url() is None:
            self.logger.error('oidc_userinfo_url is not set, unable to retrieve userinfo')
            return None
        
        try:
            with requests.get(self._get_oidc_userinfo_url(), headers={
                'Authorization': f"Bearer {self.get_accesstoken()}" 
            }) as response:
                data = response.json()
                return data
        
        except Exception as e:
            self.logger.error(f"{type(e).__name__} while retrieving oidc userinfo")
            self.logger.debug("exec_info", exc_info=True)
            return None

    def logout(self) -> bool:
        # TODO extend wrapper to dispatch correct logout method
        return self._oidc_logout()
    
    def _oidc_logout(self) -> bool:
        if self._get_oidc_end_session_url() is None:
            self.logger.error('oidc_end_session_url is not set, unable to perform logout')
            return False
        
        try:
            with requests.post(self._get_oidc_end_session_url(), 
                            headers={
                                'Accept': 'application/json',
                            }, 
                            data={
                                'client_id': self.client_id,
                                'refresh_token': self.client.token['refresh_token'],
                            }
                            ) as response:
                
                if response.status_code == 204:
                    self.client.token = {}
                    return True
                else:
                    self.logger.warning(f"got http return {response.status_code} but expected 204 while performing logout")
                    self.client.token = {} # destroy session anyways
                    return False
        
        except Exception as e:
            self.logger.error(f"{type(e).__name__} while perform logout")
            self.logger.debug("exec_info", exc_info=True)
            return False

    def is_accesstoken_valid(self) -> bool:
        if self.client.token is None:
            return False
        
        if 'access_token' not in self.client.token:
            return False
        
        valid_seconds_remaining = self.client.token['expires_at'] - time.time()
        if valid_seconds_remaining > self.__premature_refresh_time_seconds:
            return True
        
        return False
    
    def get_accesstoken(self) -> str:
        success = False

        if self.is_accesstoken_valid():
            self.logger.info('get_accesstoken(): access token still valid, returning')
            success = True
        else:
            # if we have a refresh token, try to use it
            # to refresh our session
            if 'refresh_token' in self.client.token:
                self.logger.info('get_accesstoken(): access token expired, refreshing')
                success = self._refresh_token()

            # if not succesful or no refresh_token available
            # i.e. for first login, so we start a new session            
            if not success:
                self.logger.info('get_accesstoken(): access token expired, no refresh token available, logging in')
                success = self._fetch_token()

        # if after all this, we do not have an access token
        # we were not successful
        if not self.is_accesstoken_valid():
            success = False

        if success:
            return self.client.token['access_token']
        else:
            self.logger.warn('unable to obtain access token')
            return None

class OAuthLibSessionHandlerException(Exception):
    pass