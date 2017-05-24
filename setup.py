"""
blockchainauth
==============

"""

from setuptools import setup, find_packages

setup(
    name='blockchainauth',
    version='0.3.2',
    url='https://github.com/blockstack/blockchain-auth-python',
    license='MIT',
    author='Blockstack Developers',
    author_email='hello@onename.com',
    description=("Blockchain Auth Library"),
    keywords='blockchain auth authentication id identity login bitcoin cryptocurrency',
    packages=find_packages(),
    zip_safe=False,
    install_requires=[
        'cryptography==1.8.1',
        'pybitcoin==0.9.9',
        'PyJWT==1.5.0',
        'bitmerchant==0.1.8',
        'requests==2.13.0',
        'utilitybelt==0.2.6'
    ],
    tests_require=[
        'requests-mock==1.3.0'
    ],
    test_suite='tests',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet',
        'Topic :: Security :: Cryptography',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ]
)
