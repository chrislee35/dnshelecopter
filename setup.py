#!/usr/bin/env python

from distutils.core import setup

with open('requirements.txt') as f:
    requirements = f.read().splitlines()
    
setup(name='dnshelecopter',
      version='0.0.1',
      description='DNS resolver (forwarding) with policy-enforcing functionality',
      author='Chris Lee',
      author_email='python@chrisleephd.us',
      url='https://github.com/chrislee35/dnshelecopter',
      packages=['dnshelecopter'],
      scripts=['bin/dnshelecopter'],
      install_requires=requirements,
      classifiers=[
              "Development Status :: 3 - Alpha",
              "Topic :: Utilities",
              "License :: OSI Approved :: MIT License",
          ],
      
     )