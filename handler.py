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

from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.handler import TransactionHandler

from addressing import addresser

from ledger.accounts.create_organization import organization_creation
from ledger.accounts.users import user_creation
from ledger.accounts.create_child import child_creation
from ledger.assets.create_asset import asset_creation
from ledger.assets.transfer_asset import transfer_asset_creation
from ledger.assets.share_asset import share_asset_creation
from ledger.assets.receive_asset import receive_asset_creation
#from holding import holding_creation
#from offer import offer_acceptance
#from offer import offer_closure
#from offer import offer_creation
from marketplace_payload import MarketplacePayload
from marketplace_state import MarketplaceState
from ledger.accounts.users import user_state
import logging
import traceback
#coloredlogs.install()


class MarketplaceHandler(TransactionHandler):

    @property
    def family_name(self):
        return addresser.FAMILY_NAME

    @property
    def namespaces(self):
        return [addresser.NS]

    @property
    def family_versions(self):
        return ['1.0']

    def apply(self, transaction, context):
        """
        This is the main method which handles transactions, here you need to
        handle the payload which is store in the transaction and also need to
        handle how the payload is going to affect the state of the decentralize ledger
        """
        state = MarketplaceState(context=context, timeout=3)
        userstate = user_state.UserState(context=context, timeout=3)
        payload = MarketplacePayload(payload=transaction.payload)
        try:
            if payload.is_organization_account(): #check if the transaction si actually a create_account transaction
                                            #if it is, then passon the payload and state to handle_account_creation
                                            #method present in account_creation file
                logging.info("Creating new organization account")
                organization_creation.handle_organization(
                    payload.create_organization_account(),
                    header=transaction.header,
                    state=state)

            elif payload.is_asset():
                logging.info("Creating new Asset")
                asset_creation.handle_asset_creation(
                    payload.create_asset(),
                    header=transaction.header,
                    state=state)

            elif payload.is_user_account():
                logging.info("Creating new User Account")
                user_creation.user_creation(
                    payload.create_user_account(),
                    header=transaction.header,
                    state=userstate)

            elif payload.is_child_account():
                logging.info("Creating new Child Account")
                child_creation.handle_child(
                    payload.create_child_account(),
                    header=transaction.header,
                    state=state)

            elif payload.is_transfer_asset():
                logging.info("Transferring asset")
                transfer_asset_creation.handle_transfer_asset(
                    payload.transfer_asset(),
                    header=transaction.header,
                    state=state)

            elif payload.is_share_asset():
                logging.info("Shared asset")
                share_asset_creation.handle_share_asset(
                    payload.share_asset(),
                    header=transaction.header,
                    state=state)

            elif payload.is_receive_asset():
                logging.info("Receive asset")
                receive_asset_creation.handle_receive_asset(
                    payload.receive_asset(),
                    header=transaction.header,
                    state=state)

            else:
                raise InvalidTransaction("Transaction payload type unknown.")
        except Exception as e:
                logging.error(e)
                traceback.print_exc()
                raise InvalidTransaction(e)

        """

        elif payload.is_create_holding():
            holding_creation.handle_holding_creation(
                payload.create_holding(),
                header=transaction.header,
                state=state)
        elif payload.is_create_offer():
            offer_creation.handle_offer_creation(
                payload.create_offer(),
                header=transaction.header,
                state=state)
        elif payload.is_accept_offer():
            offer_acceptance.handle_accept_offer(
                payload.accept_offer(),
                header=transaction.header,
                state=state)
        elif payload.is_close_offer():
            offer_closure.handle_close_offer(
                payload.close_offer(),
                header=transaction.header,
                state=state)
        """
