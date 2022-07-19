# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# This file is part of python-ndn.
#
# Created by liupenghui, safbag implementation.
#
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
import logging
import os
import sqlite3
from typing import Iterator
from typing import Optional, List, Tuple
from dataclasses import dataclass
from typing import Dict, Any, Mapping
from ..app_support.security_v2 import SecurityV2TypeNumber, SafeBag
from ..encoding import Component, Name, ModelField, TlvModel, ContentType, BytesField,\
    SignatureInfo, TypeNumber, RepeatedField, IncludeBase, MetaInfo, VarBinaryStr,\
    get_tl_num_size, write_tl_num, parse_and_check_tl, FormalName
from ..encoding.tlv_type import VarBinaryStr, BinaryStr, NonStrictName, FormalName
from ..encoding.tlv_var import parse_and_check_tl, shrink_length, write_tl_num, parse_tl_num, get_tl_num_size
from ..encoding.tlv_model import TlvModel, InterestNameField, BoolField, UintField, \
    SignatureValueField, OffsetMarker, BytesField, ModelField, NameField, \
    ProcedureArgument, RepeatedField

"""    
class SafeBagValue(TlvModel):
    certificate_v2 = BytesField(TypeNumber.DATA)
    encrypted_key_bag = BytesField(SecurityV2TypeNumber.ENCRYPTED_KEY_BAG)
    
    def encoded_length(self, markers: Optional[dict] = None) -> int:
        if markers is None:
            markers = {}
        return super().encoded_length(markers)

    def encode(self,
               wire: VarBinaryStr = None,
               offset: int = 0,
               markers: Optional[dict] = None) -> VarBinaryStr:
        if markers is None:
            markers = {}
        ret = super().encode(wire, offset, markers)
        return ret

    @classmethod
    def parse(cls, wire: BinaryStr, markers: Optional[dict] = None, ignore_critical: bool = False):
        if markers is None:
            markers = {}
        return super().parse(wire, markers, ignore_critical)
    
class SafeBagDataPacket(TlvModel):
    data = ModelField(SecurityV2TypeNumber.SAFE_BAG, SafeBagValue)
"""    

def encode_encrypted_key(val: VarBinaryStr) -> VarBinaryStr:
    r"""
    encode a encrypted_key.

    :param val: the buffer.
    :param length: length of val`
    """

    offset = 0
    wire = bytearray(get_tl_num_size(SecurityV2TypeNumber.ENCRYPTED_KEY_BAG) + get_tl_num_size(len(val))+len(val))
    wire_view = memoryview(wire)    
    offset += write_tl_num(SecurityV2TypeNumber.ENCRYPTED_KEY_BAG, wire_view, offset)
    offset += write_tl_num(len(val), wire_view, offset)   
    wire_view[offset:offset+len(val)] = val
    offset += len(val)
    return wire
    
def make_safebag(certificate: BinaryStr, encrypted_key: BinaryStr) -> VarBinaryStr:
    r"""
    Make a SafeBagDataPacket packet.

    :param certificate: the certificate field.
    :param encrypted_key: the encrypted pkcs8 der key field.
    """

    offset = 0
    total_length = get_tl_num_size(SecurityV2TypeNumber.SAFE_BAG) + get_tl_num_size(len(certificate)+len(encrypted_key))+len(certificate)+len(encrypted_key)
    wire = bytearray(total_length)
    wire_view = memoryview(wire)    
    offset += write_tl_num(SecurityV2TypeNumber.SAFE_BAG, wire_view, offset)
    offset += write_tl_num(len(certificate)+len(encrypted_key), wire_view, offset)   
    wire_view[offset:offset+len(certificate)] = certificate
    offset += len(certificate)
    wire_view[offset:offset+len(encrypted_key)] = encrypted_key
    return wire
    
def parse_safebag(wire: BinaryStr)-> Tuple[VarBinaryStr, VarBinaryStr]:
    r"""
    Parse a TLV encoded SafeBagDataPacket.

    :param wire: the buffer.
    :type wire: :any:`BinaryStr`
    """
    offset = 0
    typ, size_typ = parse_tl_num(wire, offset)
    offset += size_typ
    length, size_len = parse_tl_num(wire, offset)
    offset += size_len
    
    # get the length of certificate
    cert_offset = offset
    cert_total_length = 0
    typ, size_typ = parse_tl_num(wire, offset)
    offset += size_typ
    cert_total_length += size_typ

    length, size_len = parse_tl_num(wire, offset)
    offset += size_len    
    cert_total_length += size_len
    cert_total_length += length
    cert_data = memoryview(wire)[cert_offset:cert_offset+cert_total_length]
    
    offset = cert_offset+cert_total_length
     # get the length of encrypted_key
    encrypted_key_offset = offset
    encrypted_key_total_length = 0
    typ, size_typ = parse_tl_num(wire, offset)
    offset += size_typ
    encrypted_key_total_length += size_typ

    length, size_len = parse_tl_num(wire, offset)
    offset += size_len    
    encrypted_key_total_length += size_len
    encrypted_key_total_length += length    
    #we only get the PKCS8 key content, not including the encrypted_key TYPE and LENGTH
    encrypted_key = memoryview(wire)[encrypted_key_offset+size_typ+size_len:encrypted_key_offset+encrypted_key_total_length]
    
    return cert_data, encrypted_key
    

        
        
