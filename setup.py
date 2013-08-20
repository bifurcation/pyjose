#!/usr/bin/env python

from distutils.core import setup

setup(name='pyjose',
      version='0.1.0',
      description='Python security with JOSE',
      author='Richard Barnes',
      author_email='rlb@ipv.sx',
      packages=['jose', 'jose.cryptlib', 'jose.test'],
     )
