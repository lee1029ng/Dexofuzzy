# Dexofuzzy: Dalvik EXecutable Opcode Fuzzyhash

Dexofuzzy is a similarity digest hash for Android. It extracts Opcode Sequence from Dex file based on Ssdeep and generates hash that can be used for similarity comparison of Android App. Dexofuzzy created using Dex's opcode sequence can find similar apps by comparing hash.

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg) ![Latest Version](https://img.shields.io/badge/pypi-v3.3-blue.svg) ![Python Versions](https://img.shields.io/badge/python-3-blue.svg)

## Requirements

Dexofuzzy requires the following modules:

- ssdeep 3.3 or later

## Usage

```
usage: dexofuzzy [-h] [-f SAMPLE_FILENAME] [-d SAMPLE_DIRECTORY]
                 [-g N M][-s DEXOFUZZY DEXOFUZZY]
                 [-c CSV_FILENAME] [-j JSON_FILENAME]
                 [-l LOG_FILENAME]

Dexofuzzy - Dalvik EXecutable Opcode Fuzzyhash

optional arguments:
  -h, --help                     show this help message and exit
  -f SAMPLE_FILENAME, --file SAMPLE_FILENAME
                                 the sample to extract dexofuzzy
  -d SAMPLE_DIRECTORY, --directory SAMPLE_DIRECTORY
                                 the directory of samples to extract dexofuzzy
  -s DEXOFUZZY DEXOFUZZY, --score DEXOFUZZY DEXOFUZZY
                                 score the dexofuzzy of the sample
  -g N, --clustering N M         N-Gram Tokenizer and M-Partial Matching clustering based on the sample's dexofuzzy
                                 (must include the -d option by default)
  -c CSV_FILENAME, --csv CSV_FILENAME
                                 output as CSV format
  -j JSON_FILENAME, --json JSON_FILENAME
                                 output as json format
                                 (include method fuzzy or clustering)
  -l LOG_FILENAME, --error-log LOG_FILENAME
                                 output the error log
```

### Python API

To compute a Dexofuzzy of `dex file`, use `hash` function:

- _dexofuzzy(dex_binary_data)_

```python
>>> import dexofuzzy
>>> with open('classes.dex', 'rb') as dex:
...     dex_data = dex.read()
>>> dexofuzzy.hash(dex_data)
'48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'
```

- _dexofuzzy_from_file(apk_file_path or dex_file_path)_

```python
>>> import dexofuzzy
>>> dexofuzzy.hash_from_file('Sample.apk')
'48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'
>>> dexofuzzy.hash_from_file('classes.dex')
'48:U7uPrEMc0HZj0/zeGnD2KmUCNc2FuGgy9fY:UHMHZ4/zeGD2+Cap3y9Q'
```

The `compare` function returns the match between 2 hashes, an integer value from 0 (no match) to 100.

- _compare(dexofuzzy_1, dexofuzzy_2)_

```python
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
```

## Publication

- Shinho Lee, Wookhyun Jung, Sangwon Kim, Eui Tak Kim, [Android Malware Similarity Clustering using Method based Opcode Sequence and Jaccard Index](https://ieeexplore.ieee.org/iel7/8932631/8939563/08939894.pdf), In: Proceedings of the 2019 International Conference on Information and Communication Technology Convergence, ICTC, 16-18 October 2019.
- Shinho Lee, Wookhyun Jung, Sangwon Kim, Jihyun Lee, Jun-Seob Kim, [Dexofuzzy: Android Malware Similarity Clustering Method using Opcode Sequence](https://www.virusbulletin.com/uploads/pdf/magazine/2019/201911-Dexofuzzy-Android-Malware-Similarity-Clustering-Method.pdf), Virus Bulletin, 25 October 2019.
- Shinho Lee, Wookhyun Jung, Wonrak Lee, HyungGeun Oh, Eui Tak Kim, [Android Malware Dataset Construction Methodology to Minimize Bias-Variance Tradeoff](https://www.sciencedirect.com/science/article/pii/S2405959521001351/pdfft?md5=62c643429a39f8f7e31609fbd89c56a0&pid=1-s2.0-S2405959521001351-main.pdf), ICT Express, 8 October 2021.

## License

Dexofuzzy is licensed under the terms of the Apache license. See [LICENSE](https://github.com/lee1029ng/Dexofuzzy/blob/master/LICENSE) for more information.
