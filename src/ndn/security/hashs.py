# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# Created by liupenghui, package all hashs algorithms.  
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
import asyncio as aio
import sys
import os
import unittest
from Cryptodome.Hash import SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512, BLAKE2b, BLAKE2s, HMAC
from Cryptodome.Util.py3compat import b, tobytes

def SHA2_224(data: bytearray):
    h = SHA224.new()
    h.update(data)
    return h.hexdigest()
    

def SHA2_256(data: bytearray):
    h = SHA256.new()
    h.update(data)
    return h.hexdigest()

def SHA2_384(data: bytearray):
    h = SHA384.new()
    h.update(data)
    return h.hexdigest()

def SHA2_512(data: bytearray):
    h = SHA512.new()
    h.update(data)
    return h.hexdigest()

def SHA3__224(data: bytearray):
    h = SHA3_224.new(data)
    return h.digest().hex()

def SHA3__256(data: bytearray):
    h = SHA3_256.new(data)
    return h.digest().hex()

def SHA3__384(data: bytearray):
    msg = b("rrrrttt")
    h = SHA3_384.new(data)
    return h.digest().hex()

def SHA3__512(data: bytearray):
    msg = b("rrrrttt")
    h = SHA3_512.new(data)
    return h.digest().hex()

def SHA_BLAKE2b(data: bytearray):
    h = BLAKE2b.new(digest_bytes=64)
    h.update(data)
    return h.digest().hex()

def SHA_BLAKE2s(data: bytearray):
    h = BLAKE2s.new(digest_bytes=32)
    h.update(data)
    return h.digest().hex()