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
from protocompiled import share_secret_pb2
from sawtooth_sdk.processor.exceptions import InvalidTransaction
import base64
import traceback
import time
import coloredlogs, logging
coloredlogs.install()


def empty_share_secret():
    return share_secret_pb2.ShareSecret()

def empty_user():
    return user_pb2.UserAccount()

def create_empty_sig():
    return asset_pb2.Signatures()


class MnemonicState(object):

    def __init__(self, context, timeout=2):
        self._context = context
        self._timeout = timeout
        self._state_entries = []

    def get_user(self, address):
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

    def update_user_shared_secret_array(self, address, account, share_secret_address):
        if share_secret_address in account.share_secret_addresses:
            raise InvalidTransaction("Duplicacy in share_secret array of user")

        account.share_secret_addresses.append(share_secret_address)
        print ("User account {}".format(account))
        return self._context.set_state(
            {address: account.SerializeToString()}, self._timeout)


    def get_share_mnemonic(self, address):
        ##entries will be a weird list of the form
        ##[address: "318c9fa5d39e9ccd2769115795e384b8e83b3267172ae518136ac49ddc5adf71d87814"
        ##data: "\nB02dbf0f4a3defef38df754122ef7c10fee6a4bb363312367524f86d230e205d459\022$b6de5d5b-7870-49df-971e-0885986bfa96\032
        ##\006seller\"\021978-0-9956537-6-4*\0161-191-790-04532\r1-932866-82-5:\001\000"]

        entries = self._context.get_state(
            addresses=[address],
            timeout=self._timeout)

        try:
            entry = entries[0]
        except Exception as e:
            logging.info("No share mnemonic with address {} and publickey {} can be \
                        found".format(address, public_key))
            return False

        account = empty_share_secret()
        account.ParseFromString(entry.data)
        logging.info("This is the account at {} stored on blockchain \
                                {}".format(address, account))
        return account

    def update_reset_key(self, payload):
        ##entries will be a weird list of the form
        ##[address: "318c9fa5d39e9ccd2769115795e384b8e83b3267172ae518136ac49ddc5adf71d87814"
        ##data: "\nB02dbf0f4a3defef38df754122ef7c10fee6a4bb363312367524f86d230e205d459\022$b6de5d5b-7870-49df-971e-0885986bfa96\032
        ##\006seller\"\021978-0-9956537-6-4*\0161-191-790-04532\r1-932866-82-5:\001\000"]
        share_mnemonic = self.get_share_mnemonic(payload.share_secret_address)
        if not share_mnemonic:
            raise InvalidTransaction("The shared mnemonic contract doesnt exists")


        share_mnemonic.reset_key = payload.reset_key
        share_mnemonic.updated_on = payload.timestamp
        share_mnemonic.active = True

        return self._context.set_state(
                    {payload.share_secret_address: share_mnemonic.SerializeToString()}, self._timeout)


    def update_secret(self, payload):
        ##entries will be a weird list of the form
        ##[address: "318c9fa5d39e9ccd2769115795e384b8e83b3267172ae518136ac49ddc5adf71d87814"
        ##data: "\nB02dbf0f4a3defef38df754122ef7c10fee6a4bb363312367524f86d230e205d459\022$b6de5d5b-7870-49df-971e-0885986bfa96\032
        ##\006seller\"\021978-0-9956537-6-4*\0161-191-790-04532\r1-932866-82-5:\001\000"]
        share_mnemonic = self.get_share_mnemonic(payload.shared_secret_address)
        if not share_mnemonic:
            raise InvalidTransaction("The shared mnemonic contract doesnt exists")


        share_mnemonic.secret = payload.secret
        share_mnemonic.executed = True
        share_mnemonic.executed_on = payload.timestamp
        num_executions = share_mnemonic.num_executions
        if num_executions:
            share_mnemonic.num_executions = num_executions+1
        else:
            share_mnemonic.num_executions = 1

        return self._context.set_state(
                    {payload.shared_secret_address: share_mnemonic.SerializeToString()}, self._timeout)

    def shared_mnemonic_transaction(self, public_key, payload, account):
        share_secret_address = addresser.share_secret_address(public_key, payload.idx)

        logging.info("This is the share secret address <<{}>>".format(share_secret_address))



        transaction = empty_share_secret()
        transaction.public = public_key
        transaction.active = payload.active
        transaction.ownership = payload.ownership
        transaction.secret_hash = payload.secret_hash
        transaction.key = payload.key
        transaction.secret = payload.secret
        transaction.created_on=payload.created_on
        transaction.idx = payload.idx

        self.update_user_shared_secret_array(payload.user_address, account, share_secret_address)

        return self._context.set_state(
                    {share_secret_address: transaction.SerializeToString()}, self._timeout)
