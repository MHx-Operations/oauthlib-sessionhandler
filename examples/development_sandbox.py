# this is my developer sandbox to test OASH

# %%
# imports and method to setup logger

import os
import oauthlib_sessionhandler
import logging

def get_logger(level = logging.DEBUG):
    logger = logging.getLogger()
    logger.setLevel(level)

    # clean up existing stuff
    list(map(logger.removeHandler, logger.handlers))
    list(map(logger.removeFilter, logger.filters))

    handler = logging.StreamHandler()
    handler.setLevel(level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)


    logger.addHandler(handler)

    return logger

# %%
# setup logger

logger = get_logger()
logger.setLevel(logging.DEBUG)
logger.info("logging startetd")


# %%
# setup oash object

oash = oauthlib_sessionhandler.OAuthLibSessionHandler(
    wellknown_url=os.getenv('OASH_OIDCCONFIG_URL'),
    client_id=os.getenv('OASH_CLIENT'),
    client_secret=os.getenv('OASH_CLIENTSECRET'),
    username=os.getenv('OASH_USERNAME'),
    password=os.getenv('OASH_PASSWORD'),
    # password='notAValidPassword',
)

# %%
print (f"token URL from well-known: {oash._get_token_url()}")
print (f"userinfo URL from well-known: {oash._get_oidc_userinfo_url()}")
print (f"end_session URL from well-known: {oash._get_oidc_end_session_url()}")

# %%
# Manually fetch token
oash._fetch_token()

# %%
oash.is_accesstoken_valid()

# %% manually refresh token
oash._refresh_token()

# %%
import time
print (f"token remains valid for {oash.client.token['expires_at'] - time.time()} seconds")

# %%
# get oidc userinfo
oash.get_oidc_userinfo()

# %%
# *** get the access token official function ***
oash.get_accesstoken()

# %%
oash.logout()

# %%
