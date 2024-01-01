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
from setuptools import setup, find_packages

with open("README.md", encoding="UTF-8") as fd:
    README = fd.read()

setup(
    name="dexofuzzy",
    version="2.0.0",
    description="Dexofuzzy: Dalvik EXecutable Opcode Fuzzyhash",
    long_description=README,
    long_description_content_type="text/markdown",
    author="Shinho Lee",
    author_email="""lee1029ng@gmail.com""",
    url="https://github.com/lee1029ng/Dexofuzzy",
    license="Apache License 2.0",
    python_requires=">=3.5",
    include_package_data=True,
    ext_package="dexofuzzy",
    packages=find_packages(exclude=[]),
    install_requires=["ssdeep==3.4; platform_system!='Windows'"],
    entry_points={
        "console_scripts": ["dexofuzzy=dexofuzzy.cli:execute_from_command_line"],
    },
    keywords=[
        "Android", "Malware", "Opcode", "Birthmark", "Similarity digest hash",
        "N-Gram", "M-Partial Matching", "Clustering"
    ],
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.5",
    ],
)
