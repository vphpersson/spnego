from setuptools import setup, find_packages
setup(
    name='spnego',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'asn1 @ git+ssh://git@github.com/vphpersson/asn1.git#egg=asn1'
    ]
)
