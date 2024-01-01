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
"""

# Default packages
import contextlib
import os
import sys
import zipfile

# Internal packages
from dexofuzzy.core.dex.extractor import Extractor

# 3rd-party packages
if sys.platform == "win32":
    import dexofuzzy.bin as ssdeep
else:
    import ssdeep


class Generator:
    """
    This class generates dexofuzzy from the opcode.
    """

    def get_dexofuzzy(self, param):
        """
        This function generates dexofuzzy from the opcode.
        :return: dexofuzzy
        """

        try:
            opcodes_in_methods_list = self.__extract_dex_opcode(param)
            feature = ""

            for opcodes_in_methods in opcodes_in_methods_list:
                [(_, opcodes_list)] = opcodes_in_methods.items()

                for opcodes in opcodes_list:
                    feature += ssdeep.hash(opcodes, encoding="UTF-8").split(":")[1]

            return ssdeep.hash(feature, encoding="UTF-8")

        except Exception:
            GeneratorError("Unable to generate dexofuzzy")
            raise

    def __extract_dex_opcode(self, param):
        opcodes_in_methods_list = []

        try:
            if isinstance(param, bytes):
                dex_name = "Undefined"
                extractor = Extractor()
                opcodes_in_methods = extractor.get_opcodes(param)
                opcodes_in_methods_list.append({dex_name: opcodes_in_methods})

            elif isinstance(param, str):
                filetype = self.__check_file_type(param)

                if filetype == "application/zip":
                    for dex_name, dex_data in self.__extract_dex_file(param):
                        extractor = Extractor()
                        opcodes_in_methods = extractor.get_opcodes(dex_data)
                        opcodes_in_methods_list.append({dex_name: opcodes_in_methods})

                elif filetype == "application/x-dex":
                    with open(param, "rb") as dex_file:
                        dex_data = dex_file.read()

                    dex_name = os.path.basename(param)
                    extractor = Extractor()
                    opcodes_in_methods = extractor.get_opcodes(dex_data)
                    opcodes_in_methods_list.append({dex_name: opcodes_in_methods})

                else:
                    raise GeneratorError("Unable to find Dex format")

            return opcodes_in_methods_list

        except Exception:
            GeneratorError("Unable to extract opcode")
            raise

    def __check_file_type(self, file_path):
        try:
            with open(file_path, "rb") as file:
                raw_data = file.read(8)

            zip_magic_numbers = [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"]

            if raw_data[0:4] in zip_magic_numbers:
                return "application/zip"

            dex_magic_numbers = [b"dex\n035\x00", b"dex\n036\x00", b"dex\n037\x00",
                                 b"dex\n038\x00", b"dex\n039\x00", b"dex\n040\x00"]

            if raw_data[0:8] in dex_magic_numbers:
                return "application/x-dex"

            return None

        except Exception:
            GeneratorError("Unable to check file type")
            raise

    def __extract_dex_file(self, file_path):
        try:
            dex_list = []

            with contextlib.closing(zipfile.ZipFile(file_path)) as zip_file:
                for info in zip_file.infolist():
                    if(info.filename.startswith("classes") and info.filename.endswith(".dex")):
                        dex_list.append(info.filename)

                if not dex_list:
                    raise GeneratorError("Unable to find 'classes.dex' in the APK file")

                for dex_name in sorted(dex_list):
                    with zip_file.open(dex_name) as dex:
                        yield dex_name, dex.read()

        except Exception:
            GeneratorError("Unable to extract dex file")
            raise


class GeneratorError(Exception):
    """
    This class handles exceptions that occur in the process of generating dexofuzzy.
    """
