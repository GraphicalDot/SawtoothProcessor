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

from protocompiled import payload_pb2
import coloredlogs, logging
coloredlogs.install()


class MarketplacePayload(object):

    def __init__(self, payload):
        self._transaction = payload_pb2.TransactionPayload()
        self._transaction.ParseFromString(payload)

    def create_organization_account(self):
        """Returns the value set in the create_account.
        which will be the details of the account class published as a payload

        Returns:
            payload_pb2.CREATE_ORGANIZATION_ACCOUNT
        """
        #logging.debug(f"This is the create account payload in \
        #TransactionPayload {self._transaction.create_account}")

        return self._transaction.create_organization_account

    def is_organization_account(self):
        create_organization_account = \
                    payload_pb2.TransactionPayload.CREATE_ORGANIZATION_ACCOUNT
        return self._transaction.payload_type == create_organization_account


    def create_user_account(self):
        #logging.debug(f"This is the create float account  payload in \
        #TransactionPayload {self._transaction.create_float_account}")
        return self._transaction.create_user_account


    def is_user_account(self):
        user_account = payload_pb2.TransactionPayload.CREATE_USER_ACCOUNT
        return self._transaction.payload_type == user_account

    def create_share_secret(self):
        #logging.debug(f"This is the create float account  payload in \
        #TransactionPayload {self._transaction.create_float_account}")
        return self._transaction.share_secret


    def is_share_secret(self):
        share_secret = payload_pb2.TransactionPayload.SHARE_SECRET
        return self._transaction.payload_type == share_secret

    def create_activate_shares(self):
        #logging.debug(f"This is the create float account  payload in \
        #TransactionPayload {self._transaction.create_float_account}")
        return self._transaction.activate_secret


    def is_activate_shares(self):
        activate_secret = payload_pb2.TransactionPayload.ACTIVATE_SECRET
        return self._transaction.payload_type == activate_secret

    def create_execute_shares(self):
        #logging.debug(f"This is the create float account  payload in \
        #TransactionPayload {self._transaction.create_float_account}")
        return self._transaction.execute_secret


    def is_execute_shares(self):
        execute_secret = payload_pb2.TransactionPayload.EXECUTE_SECRET
        return self._transaction.payload_type == execute_secret

    def create_child_account(self):
        #logging.debug(f"This is the create float account  payload in \
        #TransactionPayload {self._transaction.create_float_account}")
        return self._transaction.create_child_account


    def is_child_account(self):
        child_account = payload_pb2.TransactionPayload.CREATE_CHILD_ACCOUNT
        return self._transaction.payload_type == child_account

    def create_asset(self):
        #logging.debug(f"This is the create asset  payload in \
        #        TransactionPayload {self._transaction.create_asset}")
        return self._transaction.create_asset


    def is_asset(self):
        create_asset = payload_pb2.TransactionPayload.CREATE_ASSET
        return self._transaction.payload_type == create_asset


    def transfer_asset(self):
        """
        logging.debug(f"This is the transfer asset  payload in \
                TransactionPayload {self._transaction.transfer_asset}")
        """
        return self._transaction.transfer_asset


    def is_transfer_asset(self):
        transfer_asset = payload_pb2.TransactionPayload.TRANSFER_ASSET
        return self._transaction.payload_type == transfer_asset


    def share_asset(self):
        return self._transaction.share_asset


    def is_share_asset(self):
        share_asset = payload_pb2.TransactionPayload.SHARE_ASSET
        return self._transaction.payload_type == share_asset

    def receive_asset(self):
        return self._transaction.receive_asset


    def is_receive_asset(self):
        receive_asset = payload_pb2.TransactionPayload.RECEIVE_ASSET
        return self._transaction.payload_type == receive_asset
