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
