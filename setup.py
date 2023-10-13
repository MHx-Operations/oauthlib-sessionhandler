from setuptools import setup
setup(
    name='oauthlib_sessionhandler',
    packages=['oauthlib_sessionhandler'],
    version='0.9.0',
    description='provides convenient session handling for OAuth, accessible via python API and CLI',
    author='Markus Hof',
    license='Apache 2.0',
    install_requires=[
        "oauthlib~=3.2",
        "requests>=2.25.1",
        "requests-oauthlib>=1.3.0",
    ]
)
