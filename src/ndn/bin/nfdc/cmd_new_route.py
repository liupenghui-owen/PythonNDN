# -----------------------------------------------------------------------------
# Copyright (C) 2019-2021 The python-ndn authors
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
import argparse
from ...app import NDNApp
from ...app_support.nfd_mgmt import make_command, parse_response
from .utils import express_interest


def add_parser(subparsers):
    parser = subparsers.add_parser('New-Route', aliases=['nr'])
    parser.add_argument('route', metavar='ROUTE',
                        help='The prefix of new or existing route')
    parser.add_argument('face_id', metavar='FACE_ID',
                        help='The next-hop to add')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    app = NDNApp()
    route = args.route
    face_id = args.face_id

    async def register_route():
        try:
            fid = int(face_id)
            cmd = make_command('rib', 'register', name=route, face_id=fid)
            res = await express_interest(app, cmd)
            msg = parse_response(res)
            print(f'{msg["status_code"]} {msg["status_text"]}')
        finally:
            app.shutdown()

    app.run_forever(after_start=register_route())
