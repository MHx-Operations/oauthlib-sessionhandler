import argparse

import oauthlib_sessionhandler.sessionhandler
import pathlib
import hashlib

from Crypto.Cipher import AES

def main():
    args = parse_args()

    oash = oauthlib_sessionhandler.OAuthLibSessionHandler(
        wellknown_url=args.oidc_config_url,
        client_id=args.client,
        username=args.username,
        password=args.password,
    )

    token_url = oash._get_token_url()

    print(f"{get_session_hash(token_url, args.client, args.username, args.password, args.clientsecret)}")


def parse_args():
    parser = argparse.ArgumentParser(description='OASH OAuthlib Session Handler')
    

    client_config_group = parser.add_argument_group('client config arguments')
    client_config_group.add_argument('--oidc-config-url', help='OIDC .well-known/openid-configuration url', metavar='oidc_config_url', dest='oidc_config_url',
                        required=True) # TODO specify endpoint directly

    client_config_group.add_argument('--client', help='OAuth client', metavar='client', dest='client',
                        required=True)

    auth_userpass_group = parser.add_argument_group('authentication w/ user/pass (LegacyApplicationClient)')
    auth_userpass_group.add_argument('--user', help='oauth2 username', metavar='username', dest='username',
                        required=False)
    auth_userpass_group.add_argument('--pass', help='oauth2 password', metavar='password', dest='password',
                        required=False)

    auth_client_group = parser.add_argument_group('authentication w/ clientsecret (BackendApplicationClient)')
    auth_client_group.add_argument('--clientsecret', help='clientsecret', metavar='clientsecret', dest='clientsecret',
                        required=False)

    options_group = parser.add_argument_group('further arguments')

    options_group.add_argument('--session-pathprefix', help='prefix to SHA1 session path files, defaults to /tmp/oash-session-', metavar='session_pathprefix', dest='session_pathprefix',
                        required=False, type=pathlib.Path, default='/tmp/oash-session-')


    # TODO logout
    args = parser.parse_args()

    auth_args_valid = False
    if args.clientsecret is not None:
        raise NotImplementedError('authenticate using clientsecret is not implemented')
    
    if args.username is not None and args.password is not None:
        auth_args_valid = True

    if not auth_args_valid:
        raise Exception('specify valid credentials either using username/password or clientsecret')

    return args    

def get_session_hash(token_url, client, username, password, clientsecret):
    unique_data = f"{token_url or ''}___{client or ''}___{username or ''}___{password or ''}___{clientsecret or ''}"

    hash = hashlib.sha1(unique_data.encode('utf-8'))
    return hash.hexdigest()

# encrypt:
# https://gist.github.com/syedrakib/d71c463fc61852b8d366

def enrcypt_data(key : str, data : str) -> str:
    cipher = AES.new(key.encode(), AES.MODE_CBC)