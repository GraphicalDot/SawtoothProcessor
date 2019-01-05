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
from .receive_secret.receive_secret_creation import ReceiveSecretState
from .share_secret.share_secret_creation import ShareSecretState
from protocompiled import organization_account_pb2

import base64
import traceback
import time
from ledger import signatures
import hashlib
import coloredlogs, logging
coloredlogs.install()



def empty_user():
    return user_pb2.UserAccount()

def create_empty_sig():
    return asset_pb2.Signatures()
def create_empty_organization():
    return organization_account_pb2.OrganizationAccount()

class SecretState(ReceiveSecretState, ShareSecretState):

    def __init__(self, context, timeout=2):
        self._context = context
        self._timeout = timeout
        self._state_entries = []
        #super(SecretState, self).__init__(context, timeout)
        ReceiveSecretState.__init__(self, context, timeout)
        ShareSecretState.__init__(self, context, timeout)

    def check_signatures(self, public, signed_nonce, nonce):
        if not signatures.ecdsa_signature_verify(public,
                                signed_nonce,
                                nonce):
            raise InvalidTransaction("Signatures with account\
                    public {} key coudnt be verified".format(public))
        else:
            logging.info("Signatures verified")
        return

    def check_nonce_hash(self, nonce, nonce_hash):
        _nonce_hash= hashlib.sha512(str(nonce).encode()).hexdigest()
        if _nonce_hash != nonce_hash:
            raise InvalidTransaction("Signatures with account\
                    public {} key coudnt be verified".format(public))
        else:
            logging.info("Nonce hash matched")
        return

    def account_at_address(self, address):

        entries = self._context.get_state(
            addresses=[address],
            timeout=self._timeout)

        try:
            entry = entries[0]
            logging.info("account data corresponding to \
                            {} is {}".format(address, entry))
        except Exception as e:
            logging.info("account data corresponding to \
                            {} is {}".format(address, None))
            return False

        account = create_empty_organization()
        account.ParseFromString(entry.data)
        return account

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


    def update_reset_key(self, share_secret, payload):
        ##entries will be a weird list of the form
        ##[address: "318c9fa5d39e9ccd2769115795e384b8e83b3267172ae518136ac49ddc5adf71d87814"
        ##data: "\nB02dbf0f4a3defef38df754122ef7c10fee6a4bb363312367524f86d230e205d459\022$b6de5d5b-7870-49df-971e-0885986bfa96\032
        ##\006seller\"\021978-0-9956537-6-4*\0161-191-790-04532\r1-932866-82-5:\001\000"]

        share_secret.reset_key = payload.reset_key
        share_secret.updated_on = payload.timestamp
        share_secret.active = True

        return self._context.set_state(
                    {payload.share_secret_address: share_secret.SerializeToString()}, self._timeout)



    def update_reset_secret(self, share_secret, payload):
        ##entries will be a weird list of the form
        ##[address: "318c9fa5d39e9ccd2769115795e384b8e83b3267172ae518136ac49ddc5adf71d87814"
        ##data: "\nB02dbf0f4a3defef38df754122ef7c10fee6a4bb363312367524f86d230e205d459\022$b6de5d5b-7870-49df-971e-0885986bfa96\032
        ##\006seller\"\021978-0-9956537-6-4*\0161-191-790-04532\r1-932866-82-5:\001\000"]

        share_secret.reset_secret = payload.reset_secret
        share_secret.updated_on = payload.timestamp
        share_secret.executed_on = payload.timestamp
        share_secret.executed = True
        if share_secret.num_executions:
            share_secret.num_executions = share_secret.num_executions + 1
        else:
            share_secret.num_executions = 1

        return self._context.set_state(
                    {payload.share_secret_address: share_secret.SerializeToString()}, self._timeout)


    def conclude_secret(self, share_secret, payload):
        ##entries will be a weird list of the form
        ##[address: "318c9fa5d39e9ccd2769115795e384b8e83b3267172ae518136ac49ddc5adf71d87814"
        ##data: "\nB02dbf0f4a3defef38df754122ef7c10fee6a4bb363312367524f86d230e205d459\022$b6de5d5b-7870-49df-971e-0885986bfa96\032
        ##\006seller\"\021978-0-9956537-6-4*\0161-191-790-04532\r1-932866-82-5:\001\000"]

        share_secret.updated_on = payload.timestamp
        share_secret.active = False
        share_secret.recovered = True
        share_secret.recovered_on = payload.timestamp

        if share_secret.num_recoveries:
            share_secret.num_recoveries = share_secret.num_recoveries + 1
        else:
            share_secret.num_recoveries = 1


        return self._context.set_state(
                    {payload.share_secret_address: share_secret.SerializeToString()}, self._timeout)
