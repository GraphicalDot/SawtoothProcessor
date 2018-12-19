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
from  addressing import addresser

def handle_asset_creation(create_asset, header, state):
    """Handles creating an Asset.

    Args:
        create_asset (CreateAsset): The transaction payload
        header (TransactionHeader): The header of the Transaction.
        state (MarketplaceState): The wrapper around the context.

    Raises:
        InvalidTransaction
            - The name already exists for an Asset.
            - The txn signer has an account

    """

    logging.info("handle asset creation function execution is starting {}".format(create_asset))
    if create_asset.flt_account_parent_pub:
        ##implies that account has not been claimed
        float_account = state.get_flt_account(
                        public_key=create_asset.flt_account_parent_pub,
                            index=create_asset.flt_account_parent_idx)
        if create_asset.idx in float_account.create_asset_idxs:
                raise ("Transaction already exists at this index")
        ##check if float_account exists
        if not float_account:
            raise InvalidTransaction("Float Account with parent public key \
                    {} doesnt exists\
                        exists".format(create_asset.flt_account_parent_pub))

        ##if the account has already been claimed then the transaction should
        ##be pushed from orgnization not the float account of organization
        if float_account.claimed:
            raise InvalidTransaction("Float account has already been claimed")
    ##zero_pub is the zeroth public key of the organization,
    ##in case of child zero_pub is the zeroth public key of the parent orgnization
    else:
        account = state.get_organization(public_key=create_asset.zero_pub)

        if not account:
                raise InvalidTransaction("Somehow claimed account doesnt have\
                account present on blockchain for address==<{}>".format(float_account))


        if create_asset.idx in account.create_asset_idxs:
            raise ("Transaction already exists at this index")


    if state.get_asset(asset_id=header.signer_public_key, index=create_asset.idx):
        raise InvalidTransaction(
            "Asset already exists with Public Key  {}".format())
    logging.info("No asset was found on asset address")

    try:
        state.set_asset(header.signer_public_key, create_asset)
    except Exception as e:
        raise InvalidTransaction("Asset with public key {}\
                    and index {} has error <<{}>>"\
                    .format(header.signer_public_key, create_asset.idx, e ))
