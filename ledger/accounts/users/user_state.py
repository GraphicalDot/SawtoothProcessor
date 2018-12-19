# Copyright 2017 Intel Corporation
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

from addressing import addresser
from protocompiled import user_pb2
from sawtooth_sdk.processor.exceptions import InvalidTransaction
import base64
import traceback
import time
import coloredlogs, logging
coloredlogs.install()


def empty_user():
    return user_pb2.UserAccount()


def create_empty_sig():
    return asset_pb2.Signatures()


class UserState(object):

    def __init__(self, context, timeout=2):
        self._context = context
        self._timeout = timeout
        self._state_entries = []

    def get_user(self, public_key):
        try:
            address = addresser.user_address(public_key, 0)
        except Exception as e:
            logging.error(e)
            raise InvalidTransaction("get_user error =={}".format(e))

        ##entries will be a weird list of the form
        ##[address: "318c9fa5d39e9ccd2769115795e384b8e83b3267172ae518136ac49ddc5adf71d87814"
        ##data: "\nB02dbf0f4a3defef38df754122ef7c10fee6a4bb363312367524f86d230e205d459\022$b6de5d5b-7870-49df-971e-0885986bfa96\032
        ##\006seller\"\021978-0-9956537-6-4*\0161-191-790-04532\r1-932866-82-5:\001\000"]

        entries = self._context.get_state(
            addresses=[address],
            timeout=self._timeout)

        logging.info("ENtries correspoding to user account address \
                {} are {}".format(address, entries))
        try:
            entry = entries[0]
        except Exception as e:
            logging.info("No user account with address {} and publickey {} can be \
                        found".format(address, public_key))
            return False

        account = empty_user()
        account.ParseFromString(entry.data)
        logging.info("This is the account at {} stored on blockchain \
                                {}".format(address, account))
        return account

    def set_user(self, public_key, payload):
        if "" in [
            payload.first_name, payload.last_name,
            payload.email, payload.phone_number]:
            raise InvalidTransaction('shouldnt be left empty')

        address = addresser.user_address(public_key, 0)

        logging.info("THis is the user address {}".format(address))
        user = empty_user()
        user.public = public_key
        user.role = payload.role
        user.phone_number = payload.phone_number
        user.pancard = payload.pancard
        user.user_id = payload.user_id
        user.email = payload.email
        user.first_name = payload.first_name
        user.last_name = payload.last_name
        user.time = payload.time
        user.indian_time = payload.indian_time
        user.deactivate = payload.deactivate
        user.deactivate_on = payload.deactivate_on

        logging.info("User before serialization %s", user)
        return self._context.set_state(
            {address: user.SerializeToString()}, self._timeout)
