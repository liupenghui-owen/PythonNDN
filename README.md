# python-ndn-gm，国密版的Python NDN底层基础库
==========


**python-ndn-gm**为支持SM2, SM3, SM4等国密算法与模式及密钥与证书管理的国密版PythonNDN软件库，包括25种算法及模式，支持的算法种类与NDN-CXX版本相同。
另外，国密版的python-ndn-gm,还支持密钥导入与导出命令，详情见代码，操作方式与NDN-CXX的密钥导入与导出命令类似，生成的密钥及Safbag与NDN-CXX版本相同，可以相互使用。
即python-ndn-gm生成的密钥及Safbag可以在NDN-CXX中使用，NDN-CXX中生成的密钥及Safbag可以在python-ndn-gm中使用。

|Test Badge|
|Code Size|
|Release Badge|
|Doc Badge|

A Named Data Networking client library with AsyncIO support in Python 3.

It supports Python >=3.8 and PyPy3 >=7.3.7.

Please see our documentation_ if you have any issues.

.. |Test Badge| image:: https://github.com/named-data/python-ndn/workflows/test/badge.svg
    :target: https://github.com/named-data/python-ndn
    :alt: Test Status

.. |Code Size| image:: https://img.shields.io/github/languages/code-size/named-data/python-ndn
    :target: https://github.com/named-data/python-ndn
    :alt: Code Size

.. |Release Badge| image:: https://img.shields.io/pypi/v/python-ndn?label=release
    :target: https://pypi.org/project/python-ndn/
    :alt: Release Ver

.. |Doc Badge| image:: https://readthedocs.org/projects/python-ndn/badge/?version=latest
    :target: https://python-ndn.readthedocs.io/en/latest/?badge=latest
    :alt: Doc Status

.. _documentation: https://python-ndn.readthedocs.io/en/latest
