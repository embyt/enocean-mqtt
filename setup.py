"""setup module for enoceanmqtt"""

# prefer setuptools over distutils
from setuptools import setup, find_packages

# needed packages
REQUIRES = [
    'enocean',
    'paho-mqtt',
]

setup(
    name='enoceanmqtt',
    version='0.1.0',
    description='',
    url='http://romor.github.io/enocean-mqtt',
    author='Roman Morawek',
    author_email='maemo@morawek.at',
    license='GPLv3',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
    ],
    keywords='enOcean MQTT IoT',
    packages=find_packages(exclude=['contrib', 'docs', 'tests*']),
    install_requires=REQUIRES,

    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # pip to create the appropriate form of executable for the target platform.
    entry_points={
        'console_scripts': [
            'enoceanmqtt=enoceanmqtt',
        ],
    },
)
