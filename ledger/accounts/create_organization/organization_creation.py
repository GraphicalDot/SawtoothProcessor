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
import coloredlogs, logging
coloredlogs.install()

def handle_organization(create_account, header, state):
    """Handles creating an Account.

    Args:
        create_account (CreateAccount): The transaction.
        header (TransactionHeader): The header of the Transaction.
        state (MarketplaceState): The wrapper around the Context.

    Raises:
        InvalidTransaction
            - The public key already exists for an Account.
    """
    if create_account.role != "ADMIN":
        ##because admin orgnization account will not have a float account
        float_account = state.get_flt_account(public_key=create_account.parent_pub,
                        index=create_account.parent_idx)


        if float_account.claimed_by:

            message = "This account has already been claimed by {}".format(float_account.claimed_by)
            logging.error(message)
            raise InvalidTransaction(message)

    ##this means the float__account.claimed_by dshould have users zeroth public ker from
    ##which account adddress must have been created
    """
    if float_account.claimed_by:
        if float_account.claimed_by != header.signer_public_key:
            message = "This account has been claimed by somebody else, FATAL error\
                app shouldnt proceed"
            logging.error(message)
            raise InvalidTransaction(message)

    """

    ##users zeroth public key has signed this transaction
    if state.get_organization(public_key=header.signer_public_key):
        raise InvalidTransaction("Account with public key {} already \
                                 been claimed".format(header.signer_public_key))

    state.set_organization(
            public_key=header.signer_public_key,
            account_payload=create_account
            )
    #except Exception as e:
    #    raise InvalidTransaction("Account with public key {}\
    #     has error in registration fields {}".format(header.signer_public_key ,e))
