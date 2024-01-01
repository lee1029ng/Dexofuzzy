"""
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Dexofuzzy: Dalvik EXecutable Opcode Fuzzyhash

Dexofuzzy is a similarity digest hash for Android. It extracts Opcode
Sequence from Dex file based on Ssdeep and generates hash that can be
used for similarity comparison of Android App. Dexofuzzy created using
Dex's opcode sequence can find similar apps by comparing hash.

Dexofuzzy API usage:

... hash(dex_binary_data)

    >>> import dexofuzzy
    >>> with open('classes.dex', 'rb') as dex:
    ...     dex_data = dex.read()
    >>> dexofuzzy.hash(dex_data)
    '48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'

... hash_from_file(apk_file_path or dex_file_path)

    >>> import dexofuzzy
    >>> dexofuzzy.hash_from_file('Sample.apk')
    '48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'
    >>> dexofuzzy.hash_from_file('classes.dex')
    '48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'

... compare(dexofuzzy_1, dexofuzzy_2)

    >>> import dexofuzzy
    >>> with open('classes.dex', 'rb') as dex:
    ...     dex_data = dex.read()
    >>> hash1 = dexofuzzy.hash(dex_data)
    >>> hash1
    '48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'
    >>> hash2 = dexofuzzy.hash_from_file('classes2.dex')
    >>> hash2
    '48:B2KmUCNc2FuGgy9fbdD7uPrEMc0HZj0/zeGn5:B2+Cap3y9pDHMHZ4/zeG5'
    >>> dexofuzzy.compare(hash1, hash2)
    50

:license: Apache 2.0, see LICENSE for more details.
"""

# Default packages
import sys

# Internal packages
from .core.generator import Generator

# 3rd-party packages
if sys.platform == "win32":
    import dexofuzzy.bin as ssdeep
else:
    import ssdeep


def compare(dexofuzzy_1, dexofuzzy_2):
    """
    This function computes the match score between two dexofuzzy signatures.
    :param dexofuzzy_1: string
    :param dexofuzzy_2: string
    :return: A value from zero to 100 indicating the match score of the two signatures
    """

    return ssdeep.compare(dexofuzzy_1, dexofuzzy_2)


def hash(dex_data):
    """
    This function compute the dexofuzzy of a dex binary data.
    :param dex_data: bytes
    :return: The dexofuzzy of the dex binary data
    """

    if not isinstance(dex_data, bytes):
        raise TypeError("must be of bytes type")

    generator = Generator()
    dexofuzzy = generator.get_dexofuzzy(dex_data)

    return dexofuzzy


def hash_from_file(file_path):
    """
    This function compute the dexofuzzy of the apk file or the dex file.
    :param file_path: string
    :return: The dexofuzzy of the dex file
    """

    if not isinstance(file_path, str):
        raise TypeError("must be of string type")

    generator = Generator()
    dexofuzzy = generator.get_dexofuzzy(file_path)

    return dexofuzzy
