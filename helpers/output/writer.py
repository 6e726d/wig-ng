#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# wig-ng - Wireless Information Gathering New Generation
# Copyright (C) 2019 - Andrés Blanco (6e726d) <6e726d@gmail.com>
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

from collections import OrderedDict

# Verbose Count
OUTPUT_INFO = 0
OUTPUT_VERBOSE = 1
OUTPUT_DEBUG = 2


def get_device_information_dict(mac_address, module_name, elements):
    """
    Function that returns an ordered dictionary with the device information.
    """
    aux = OrderedDict()
    aux[""] = mac_address
    aux["Module"] = module_name
    for title, value in elements.items():
        aux[title] = value
    return aux
