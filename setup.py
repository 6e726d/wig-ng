#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# wig-ng - Wireless Information Gathering New Generation
# Copyright (C) 2022 - Andrés Blanco (6e726d) <6e726d@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import glob

from distutils.core import setup


PACKAGE_NAME = 'wig-ng'

VERSION_MAJOR = 0
VERSION_MINOR = 2

setup(name=PACKAGE_NAME,
      version='{}.{}'.format(VERSION_MAJOR, VERSION_MINOR),
      description='WIG-ng is a free and open source utility for WiFi device fingerprinting.',
      url='https://github.com/6e726d/wig-ng',
      author='Andres Blanco',
      author_email='6e726d@gmail.com',
      console = [{'script': PACKAGE_NAME}],
      license='GPLv2',
      platforms=['Unix'],
      packages=['wig',
                'wig.consumers',
                'wig.producers',
                'wig.helpers',
                'wig.helpers.network',
                'wig.helpers.output'],
      scripts=glob.glob(os.path.join('wig', 'wig-ng.py')),
      install_requires=['pcapyplus', 'impacket', 'setproctitle'],
      classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 3',
        ],
      download_url="https://github.com/6e726d/wig-ng/archive/refs/tags/0.2.tar.gz"
)