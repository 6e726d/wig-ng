#!/usr/bin/env python
# This file is Copyright David Francos Cuartero, licensed under the GPL2 licens>

from distutils.core import setup

setup(name='wig-ng',
      version='0.1',
      description='WIG-ng is a free and open source utility for WiFi device fingerprinting',
      author='6e726d',
      console = [{"script": "wig-ng" }],
      url='https://github.com/6e726d/wig-ng',
      license='GPLv2',
      classifiers=[
          'Development Status :: 4 - Beta',
      ],
      packages=['consumers', 'helpers', 'helpers.network', 'helpers.output', 'producers'],
      scripts=['wig-ng.py'],
     )
