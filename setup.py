from setuptools import setup, find_packages
setup(
    name='spnego',
    version='0.11',
    packages=find_packages(),
    install_requires=[
        'asn1 @ git+https://github.com/vphpersson/asn1.git#egg=asn1'
    ]
)
