import re
from setuptools import setup, find_packages


with open('coinaddrvalidator/__init__.py', 'rt') as fd:
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
                        fd.read(), re.MULTILINE).group(1)

if not version:
    raise RuntimeError('Cannot find version information')

try:
    from m2r import parse_from_file
    long_description = parse_from_file('README.md')
except ImportError:
    with open('README.md') as fd:
        long_description = fd.read()


setup(
    name='coinaddrvalidator',
    version=version,
    description='A crypto-currency address inspection/validation library.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    keywords=[
        'bitcoin',
        'litecoin',
        'altcoin',
        'ethereum',
        'address',
        'validation',
        'inspection',
    ],
    author='Mohammad Aghamir',
    author_email='maghamir@nobitex.net',
    maintainer='Mohammad Aghamir',
    maintainer_email='maghamir@nobitex.net',
    url='https://github.com/nobitex/coinaddrvalid',
    download_url=(
        'https://github.com/nobitex/coinaddrvalid/tarball/v%s' % version),
    license='MIT',
    install_requires=[
        'attrs>=24.0.0',
        'pycryptodome>=3.6.1',
        'base58check>=1.0.1',
        'zope.interface>=4.4.3',
        'blake256>=0.1.1',
        'cbor>=1.0.0',
        'bech32>=1.1.0',
        'groestlcoin-hash2>=1.1.1',
        'zope',
        'zope.interface>=4.4.3',
    ],
    zip_safe=False,
    packages=find_packages(),
    package_data={'': ['LICENSE']},
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Software Development',
        'Topic :: Security :: Cryptography',
        'Topic :: Text Processing',
        'Topic :: Utilities',
        "Topic :: Software Development :: Libraries :: Python Modules",
    ]
)
