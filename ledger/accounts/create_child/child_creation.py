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
from ledger import signatures
import hashlib

def handle_child(child_account, header, state):
    """Handles creating an Account.

    Args:
        child_account (CreateChildAccount): The transaction.
        header (TransactionHeader): The header of the Transaction.
        state (MarketplaceState): The wrapper around the Context.

    Raises:
        InvalidTransaction
            - The public key already exists for an Account.
    Process:
        Checks:

            Check whether the child orgnisation exists on the blockchain
            Check whether the child account exists on the blockchain
            Check whether the signatures matches with the orgnisation
            zeroth account key
        Actions:
            CReate child account using header.signer_public_key and parent_idx
            address whill be generate as addresser.child_account_address
            Append parent_idx under orgnisation child_account_idxs array
    """

    ##users zeroth public key has signed this transaction
    if not state.get_organization(public_key=child_account.parent_zero_pub):
        raise InvalidTransaction("THe parent orgnisation {} doest exists on the\
                Orgs zeroth public key".format(child_account.org_name,\
                    child_account.parent_zero_pub))


    if  state.get_child(public_key=header.signer_public_key,
                                                index=0):
        raise InvalidTransaction("THe child for orgnisation {} already\
                exists on the with public_key{} at index {} with orgs zeroth \
                public key {}".format(child_account.org_name,\
                header.signer_public_key, child_account.parent_idx,\
                child_account.parent_zero_pub))



    if child_account.nonce_hash != hashlib.sha224(str(child_account.nonce).encode()).hexdigest():
            raise InvalidTransaction("Nonce hash {} doesnt match with hash of the nonce {}\
                    ".format(child_account.nonce_hash, child_account.nonce))
    else:
        logging.info("Nobody tampered with nonce and nonce hash")

    ##checking the signatures whether the parent actually created this transaction
    if not signatures.ecdsa_signature_verify(child_account.parent_zero_pub,
                                child_account.signed_nonce,
                                child_account.nonce):
            raise InvalidTransaction("Signatures with account parent_pub \
                            coudnt be verified")
    else:
        logging.info("Signatures verified")

    state.set_child(
            public_key=header.signer_public_key,
            payload=child_account
            )
    #except Exception as e:
    #    raise InvalidTransaction("Account with public key {}\
    #     has error in registration fields {}".format(header.signer_public_key ,e))
