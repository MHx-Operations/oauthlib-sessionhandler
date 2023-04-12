# oash (oauthlib-sessionhandler)

**OA**uthlib-**S**ession**H**andler provides convenient session handling for
OAuth. It's intended usage is a lazy interface for OAuth Flows using a CLI
command to be used in shell scripts or via python API which can be used in other
components.
One does not have to take care about login or refresh token if expired, one can
simply call ``oash`` (CLI) or ``get_accesstoken()`` method (API) every request, OASH
will take care about the rest.

This project was tested under openid-connect conditions in environments using keycloak
and AzureAD.

## Installation

~~~text
pip install git+https://github.com/MHx-Operations/oauthlib-sessionhandler.git#egg=oauthlib_sessionhandler
~~~

## Usage

### API

see [examples/](examples/) folder

### CLI

run ``oash --help`` for detailed usage of command line parameters

OASH provideds persistent sessions saved to ``/tmp/oash-session-...`` (default)
to provide information handover for subsequent requests/commands or an issued
logout after everything is done.

~~~bash
curl -H "Authorization: Bearer $(oash --user svc_whatever --pass yourS3cret --client demo_client --oidc-config-url https://auth-test.mhx.at/auth/realms/mhx/.well-known/openid-configuration)" \
  http://proteceted.host/resource
~~~

~~~bash
# optionally logout after everthing is done
oash --user svc_whatever --pass yourS3cret --client demo_client --oidc-config-url https://auth-test.mhx.at/auth/realms/mhx/.well-known/openid-configuration --logout
~~~

Note according to persistence files:

- Session persistence path prefix can be overridden by ``--session-pathprefix`` (defaults
to ``/tmp/oash-session-``). A SHA1 hash of (tokenurl, client, username/password
or client_secret) will be appended to this path prefix to ensure uniqueness of
sessions as well as anonymized parameters
- session files will be encrypted using a symmetric method protected by
  password/client_secret (therefore it is part of the hash)
- session files will be removed when performing logout

## Development

### Dev Environment Setup

~~~bash
# create virtual environment
python3 -m venv .venv

# enter virtual environment 
source .venv/bin/activate

# install requirements
pip3 install -r requirements.txt

# install additional dev requirements (used for interactive development)
pip3 install ipykernel autopep8 notebook
~~~

### Resources and Notes

Links:

- [https://pypi.org/project/oauthlib/](https://pypi.org/project/oauthlib/)
- [https://github.com/requests/requests-oauthlib](https://github.com/requests/requests-oauthlib)
- [https://github.com/max-bytes/omnikeeper-client-python](https://github.com/max-bytes/omnikeeper-client-python)
- [https://realpython.com/pypi-publish-python-package/#prepare-your-package-for-publication](https://realpython.com/pypi-publish-python-package/#prepare-your-package-for-publication)

To do:

- [ ] CLI
- [ ] package pip installation
- [ ] package for pypi.org
