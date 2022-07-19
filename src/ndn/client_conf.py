# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# This file is part of python-ndn.
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
import os
import sys
from configparser import ConfigParser
from .platform import Platform
from .security.keychain import Keychain, KeychainSqlite3
from .security.tpm import TpmFile

from .transport.stream_socket import Face, UnixFace, TcpFace
if sys.platform == 'darwin':
    from .security.tpm.tpm_osx_keychain import TpmOsxKeychain
if sys.platform == 'win32':
    from .security.tpm.tpm_cng import TpmCng


def read_client_conf():
    def get_path() -> str:
        paths = Platform().client_conf_paths()
        for p_str in paths:
            p = os.path.expandvars(p_str)
            if os.path.exists(p):
                return p
        return ''

    def resolve_location(item: str, value: str) -> str:
        nonlocal path
        sp = value.split(':')
        if len(sp) == 1:
            scheme = value
            loc = ''
        else:
            scheme, loc = sp
        if not loc or not os.path.exists(loc):
            if loc and (path is not None):
                loc = os.path.join(os.path.dirname(path), loc)
            if not loc or not os.path.exists(loc):
                if item == 'pib':
                    paths = Platform().default_pib_paths()
                else:
                    paths = Platform().default_tpm_paths()
                for p_str in paths:
                    p = os.path.expandvars(p_str)
                    if os.path.exists(p):
                        loc = p
                        break
        return ':'.join((scheme, loc))

    path = get_path()
    ret = {
        'transport': Platform().default_transport(),
        'pib': Platform().default_pib_scheme(),
        'tpm': Platform().default_tpm_scheme()
    }
    if path:
        parser = ConfigParser()
        text = '[DEFAULT]\n'
        with open(path) as f:
            text += f.read()
        parser.read_string(text)
        for key in ret.keys():
            try:
                ret[key] = parser['DEFAULT'][key]
            except KeyError:
                pass
    for key in ret.keys():
        try:
            ret[key] = os.environ[f'NDN_CLIENT_{key.upper()}']
        except KeyError:
            pass
    for key in ['pib', 'tpm']:
        ret[key] = resolve_location(key, ret[key])
    return ret


def default_keychain(pib: str, tpm: str) -> Keychain:
    pib_scheme, pib_loc = pib.split(':', 1)
    tpm_scheme, tpm_loc = tpm.split(':', 1)
    if tpm_scheme == 'tpm-file':
        tpm = TpmFile(tpm_loc)
    elif tpm_scheme == 'tpm-osxkeychain':
        tpm = TpmOsxKeychain()
    elif tpm_scheme == 'tpm-cng':
        tpm = TpmCng()
    else:
        raise ValueError(f'Unrecognized tpm scheme: {tpm}')
    if pib_scheme == 'pib-sqlite3':
        pib = KeychainSqlite3(os.path.join(pib_loc, 'pib.db'), tpm)
    else:
        raise ValueError(f'Unrecognized pib scheme: {pib}')
    return pib


def default_face(face: str) -> Face:
    scheme, uri = face.split('://')
    if scheme == 'unix':
        return UnixFace(uri)
    elif scheme == 'tcp' or scheme == 'tcp4':
        if uri.find(':') >= 0:
            host, port = uri.split(':')
            port = port
        else:
            host = uri
            port = 6363
        return TcpFace(host, int(port))
    else:
        raise ValueError(f'Unrecognized face: {face}')

