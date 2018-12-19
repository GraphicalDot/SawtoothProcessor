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

from protocompiled import payload_pb2


from .common import make_header_and_batch

import coloredlogs, logging
coloredlogs.install()




def create_child_account(**in_data):
    inputs = [
            addresser.create_organization_account_address(
                        account_id=in_data["parent_zero_pub"],
                        index=0),
            addresser.child_account_address(
                account_id=in_data["txn_key"].get_public_key().as_hex(),
                index=0),
                ]


    outputs = [
        addresser.create_organization_account_address(
                    account_id=in_data["parent_zero_pub"],
                    index=0),
        addresser.child_account_address(
            account_id=in_data["txn_key"].get_public_key().as_hex(),
            index=0),
            ]

    account = payload_pb2.CreateChildAccount(
            parent_zero_pub=in_data["parent_zero_pub"],
            parent_idx=in_data["parent_idx"],
            parent_role=in_data["parent_role"],

            org_name=in_data["org_name"],
            first_name=in_data["first_name"],
            last_name=in_data["last_name"],

            user_id=in_data["user_id"],
            pancard = in_data["pancard"],
            gst_number=in_data["gst_number"],
            tan_number=in_data["tan_number"],
            phone_number = in_data["phone_number"],
            email=in_data["email"],

            time=in_data["time"],
            indian_time=in_data["indian_time"],
            role = in_data["role"],

            deactivate=in_data["deactivate"],
            deactivate_on=in_data["deactivate_on"],

            nonce=in_data["nonce"],
            nonce_hash=in_data["nonce_hash"],
            signed_nonce=in_data["signed_nonce"],

            )

    logging.info(account)
    logging.info(f"THe address for the user on blockchain {inputs[0]}")

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.CREATE_CHILD_ACCOUNT,
        create_child_account=account)

    logging.info(payload)
    return make_header_and_batch(
        payload=payload,
        inputs=inputs,
        outputs=outputs,
        txn_key=in_data["txn_key"],
        batch_key=in_data["batch_key"])

def create_organization_account(**in_data):
    """Create a CreateAccount txn and wrap it in a batch and list.
    need to change two addresses

    create a account from user zeroth key
    edit float_accout address from parent nindex key and marked it claimed
    Args:
        txn_key (sawtooth_signing.Signer): The Txn signer key pair.
        batch_key (sawtooth_signing.Signer): The Batch signer key pair.
        label (str): The account's label.
        description (str): The description of the account.

    Returns:
        tuple: List of Batch, signature tuple
    """

    inputs = [addresser.create_organization_account_address(
                        account_id=in_data["txn_key"].get_public_key().as_hex(),
                        index=0),
                ]


    outputs = [addresser.create_organization_account_address(
                        account_id=in_data["txn_key"].get_public_key().as_hex(),
                        index=0),

        ]

    if in_data["role"] != "ADMIN":
        inputs.append(addresser.float_account_address(
                        account_id=in_data["parent_pub"],
                        index=in_data["parent_idx"]))
        outputs.append(addresser.float_account_address(
                     account_id=in_data["parent_pub"],
                     index=in_data["parent_idx"]))


    if in_data.get("parent_pub"):
        logging.info(f"This is the parent pub {in_data['parent_pub']}")

    account = payload_pb2.CreateOrganizationAccount(
            role = in_data["role"],
            parent_role=in_data["parent_role"],
            phone_number = in_data["phone_number"],
            pancard = in_data["pancard"],
            user_id=in_data["user_id"],
            email=in_data["email"],
            org_name=in_data["org_name"],
            gst_number=in_data["gst_number"],
            tan_number=in_data["tan_number"],
            time=in_data["time"],
            indian_time=in_data["indian_time"],
            parent_zero_pub=in_data["parent_zero_pub"],
            deactivate=in_data["deactivate"],
            deactivate_on=in_data["deactivate_on"],
            create_asset_idxs=in_data["create_asset_idxs"],
            parent_pub=in_data["parent_pub"],
            parent_idx=in_data["parent_idx"],
            float_account_address=in_data["float_account_address"],

            )

    logging.info(account)
    logging.info(f"THe address for the user on blockchain {inputs[0]}")

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.CREATE_ORGANIZATION_ACCOUNT,
        create_organization_account=account)

    logging.info(payload)
    return make_header_and_batch(
        payload=payload,
        inputs=inputs,
        outputs=outputs,
        txn_key=in_data["txn_key"],
        batch_key=in_data["batch_key"])



def create_float_account(**in_data):
    """Create a CreateAccount txn and wrap it in a batch and list.

    Args:
        txn_key(sawtooth_signing.Signer): signer created from user zeroth public key
        parent_zero_pub(string): zeroth account key of the pub who floated this trnasaction
        batch_key(sawtooth_signing.Signer):  signer created from QCI mnemonic zero private key,
        pancard(str): pancard of the user ,
        phone_number(str): phone_number of the user,
        email(str): email of the user,
        claimed(bool): If this float account is claimed or not,
        claimed_by(str): Public key of the user for whom this float_acc transaction,
        create_asset_index(int): random key index at which the first asset was created,
        parent_pub(str): public key of the parent ,
        parent_idx(str): Required to be appened to parent accoutn flt_key_inds, key_index,
        time=time.time();
        indian_time=indian_time_stamp(),
        claimed_on(str): Date on which this flt account was claimed and converted to create account)
        parent_zero_pub: parent zero pub required for calcualting parent address
        parent_role=parent["role"],
        user_role=user_data["role"]

    Returns:
        tuple: List of Batch, signature tuple
    """
    logging.info(f"THis is the data received in trsaction ceratrion {in_data}")

    inputs = [addresser.create_organization_account_address(
                        account_id=in_data["parent_zero_pub"],
                        index=0),
            addresser.float_account_address(
                        account_id=in_data["txn_key"].get_public_key().as_hex(),
                        index=in_data["parent_idx"]
         )
        ]

    logging.info(f"THe account address for the parent on blockchain {inputs[0]}")
    logging.info(f"THe float account address for the user {inputs[1]}")
    outputs = [addresser.create_organization_account_address(
                            account_id=in_data["parent_zero_pub"],
                            index=0),
                addresser.float_account_address(
                            account_id=in_data["txn_key"].get_public_key().as_hex(),
                            index=in_data["parent_idx"]
             )
            ]


    if in_data["child_zero_pub"]:

        child_address = addresser.child_account_address(
                    account_id=in_data["child_zero_pub"],
                    index=0
        )
        logging.info(f"CHILD address is {child_address}")
        inputs.append(child_address)
        outputs.append(child_address)


    logging.info(f"INPUTS ADDRESSES --<{inputs}>--")
    logging.info(f"OUTPUTS ADDRESSES --<{outputs}>--")


    float_account = payload_pb2.CreateFloatAccount(
              claimed_on=in_data["claimed_on"],
              org_name=in_data["org_name"],
              pancard=in_data["pancard"],
              gst_number=in_data["gst_number"],
              tan_number=in_data["tan_number"],
              phone_number=in_data["phone_number"],
              email=in_data["email"],
              claimed=in_data["claimed"],
              claimed_by=in_data["claimed_by"],
              create_asset_idxs=in_data["create_asset_idxs"],
              parent_idx=in_data["parent_idx"],
              time=in_data["time"],
              indian_time=in_data["indian_time"],
              parent_role=in_data["parent_role"],
              role=in_data["role"],
              parent_zero_pub=in_data["parent_zero_pub"],
              nonce=in_data["nonce"],
              nonce_hash=in_data["nonce_hash"],
              signed_nonce=in_data["signed_nonce"],
              child_zero_pub=in_data["child_zero_pub"]
    )

    logging.info(float_account)
    logging.info(f"THe serialized protobuf for float_account is {float_account}")

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.CREATE_FLOAT_ACCOUNT,
        create_float_account=float_account)

    return make_header_and_batch(
        payload=payload,
        inputs=inputs,
        outputs=outputs,
        txn_key=in_data["txn_key"],
        batch_key=in_data["batch_key"])

def receive_asset(**in_data):
    """
    """
    address = addresser.receive_asset_address(
                asset_id=in_data["txn_key"].get_public_key().as_hex(),
                index=in_data["idx"])

    inputs = [in_data["org_address"], address]
    outputs=[in_data["org_address"], address]
    logging.info(in_data)
    if in_data["child_zero_pub"]:

        child_address = addresser.child_account_address(
                    account_id=in_data["child_zero_pub"],
                    index=0
        )
        logging.info(f"CHILD address is {child_address}")
        inputs.append(child_address)
        outputs.append(child_address)

    if in_data["receive_asset_details"]:
        receive_asset_details = payload_pb2.ReceiveAssetDetails(
            name=in_data["receive_asset_details"]["name"],
            description=in_data["receive_asset_details"]["description"],
            )
    receive_asset = payload_pb2.CreateReceiveAsset(
            _id_=in_data["_id_"],
            time=in_data["time"],
            indiantime=in_data["indiantime"],
            idx=in_data["idx"],
            at_which_asset_expires=in_data["at_which_asset_expires"],
            org_name=in_data["org_name"],
            org_address=in_data["org_address"],
            org_role=in_data["org_role"],
            org_zero_pub=in_data["org_zero_pub"],
            receive_asset_details=receive_asset_details,
            child_zero_pub=in_data["child_zero_pub"],
            signed_nonce=in_data["signed_nonce"],
            nonce=in_data["nonce"],
            nonce_hash=in_data["nonce_hash"],
            unique_code_hash=in_data["unique_code_hash"],
            encrypted_unique_code=in_data["encrypted_unique_code"],
            encrypted_admin_unique_code=in_data["encrypted_admin_unique_code"]
    )

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.RECEIVE_ASSET,
        receive_asset=receive_asset)
    logging.info(payload)
    return make_header_and_batch(
        payload=payload,
        inputs=inputs,
        outputs=outputs,
        txn_key=in_data["txn_key"],
        batch_key=in_data["batch_key"])

def share_asset(**in_data):
    """
    To share asset by the asset_owner to any account address

    inputs will have the following addresses
        Asset transaction addresses in which share_with array needs to
        be appended
        Shareasset transaction address
    """

    inputs = [in_data["original_asset_address"],
            addresser.share_asset_address(
                in_data["txn_key"].get_public_key().as_hex(),
                in_data["idx"]),
            in_data["issuer_account_address"] #issuer_account_address
    ]

    outputs = [in_data["original_asset_address"],
            addresser.share_asset_address(
                in_data["txn_key"].get_public_key().as_hex(),
                in_data["idx"]),
            in_data["issuer_account_address"] #issuer_account_address

    ]


    share_asset = payload_pb2.CreateShareAsset(
            key=in_data["key"],
            url=in_data["url"],
            master_key=in_data["master_key"],
            master_url=in_data["master_url"],
            time=in_data["time"],
            indiantime=in_data["indiantime"],
            file_name=in_data["file_name"],
            file_hash=in_data["file_hash"],
            original_asset_address=in_data["original_asset_address"],
            revoked_on=in_data["revoked_on"],
            #details=in_data["details"],
            idx=in_data["idx"],
            account_signature=in_data["account_signature"],
            asset_signature=in_data["asset_signature"],
            nonce=in_data["nonce"],
            nonce_hash=in_data["nonce_hash"],
            to_org_name=in_data["to_org_name"],
            to_org_address=in_data["to_org_address"],
            issuer_account_address=in_data["issuer_account_address"],
            receive_asset_address = in_data["receive_asset_address"],
            child_zero_pub=in_data["child_zero_pub"],
            unique_code_hash=in_data["unique_code_hash"],

    )

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.SHARE_ASSET,
        share_asset=share_asset)

    return make_header_and_batch(
        payload=payload,
        inputs=inputs,
        outputs=outputs,
        txn_key=in_data["txn_key"],
        batch_key=in_data["batch_key"])


def transfer_asset(**in_data):
    inputs = [in_data["receiver_address"], in_data["issuer_address"]]
    outputs = [in_data["receiver_address"], in_data["issuer_address"]]


    transfer_asset = payload_pb2.CreateTransferAsset(
            key=in_data["key"],
            url=in_data["url"],
            time=in_data["time"],
            indiantime=in_data["indiantime"],
            file_name=in_data["file_name"],
            file_hash=in_data["file_hash"],
            master_key=in_data["master_key"],
            master_url=in_data["master_url"],
            expired_on=in_data["expired_on"],
            scope=in_data["scope"],
            receiver_address=in_data["receiver_address"],
            issuer_address=in_data["issuer_address"],
            issuer_pub=in_data["issuer_pub"],
            issuer_zero_pub=in_data["issuer_zero_pub"],
            signed_nonce=in_data["signed_nonce"],
            nonce=in_data["nonce"],
            issuer_child_zero_pub=in_data["issuer_child_zero_pub"],

    )

    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.TRANSFER_ASSET,
        transfer_asset=transfer_asset)

    return make_header_and_batch(
        payload=payload,
        inputs=inputs,
        outputs=outputs,
        txn_key=in_data["txn_key"],
        batch_key=in_data["batch_key"])


def create_asset(**in_data):
    """
    Inputs will have asset_address,
        account_address (The key index will be appended to the account address)
        float_accout (if the user only has a float_account till now, key_index will be
            appended to the float_account address)
        child_account_address (In case the asset being created by the child)
    """


    ##TODO: Processor side : Float this asset and make change to create_asset_idxs
    ## to either float_Account_Address or create_Account_Address depending upon
    ##whther the user has been claimed or not
    inputs = [addresser.create_asset_address(
                    asset_id=in_data["txn_key"].get_public_key().as_hex(),
                    index=in_data["idx"]),
            ]

    outputs = [addresser.create_asset_address(
                    asset_id=in_data["txn_key"].get_public_key().as_hex(),
                    index=in_data["idx"])
            ]



    ##ideally if account is claimed, we should have nothing to do with float account
    ## but we are sending both addresses to the processor and let processor handle
    ## the logic i.e float_account should exists and is_claimed shall be true
    ##to append create_asset_idxs to the account_transaction
    if not in_data["is_acc_claimed"]:
        ##implies user havent claimed his float_account_address, so the
        ## create_asset_idx aill be chnaged on flt_account_addresslogging.info("Float account parent pub %s"%in_data["flt_account_parent_pub"])
        logging.info("Float account parent idx %s"%str(in_data["flt_account_parent_idx"]))
        float_account_address = addresser.float_account_address(
                    account_id=in_data["flt_account_parent_pub"],
                    index=in_data["flt_account_parent_idx"])
        inputs.append(float_account_address)
        outputs.append(float_account_address)
    else:

        account_address = addresser.create_organization_account_address(
            account_id=in_data["zero_pub"],
            index=0
            )


        inputs.append(account_address)
        outputs.append(account_address)

    if in_data["child_zero_pub"]:
        child_address = addresser.child_account_address(
                    account_id=in_data["child_zero_pub"],
                    index=0
                    )
        inputs.append(child_address)
        outputs.append(child_address)

    if in_data["scope"]:
        scope = payload_pb2.PayloadScope(
            group=in_data["scope"]["group"],
            sub_group=in_data["scope"]["sub_group"],
            field=in_data["scope"]["field"],
            nature=in_data["scope"]["nature"],
            operations=in_data["scope"]["operations"],
            description=in_data["scope"]["description"],
            )
    else:
        scope=None

    logging.info(f"Input Address<<{inputs}>>")
    logging.info(f"Output Address<<{outputs}>>")

    asset = payload_pb2.CreateAsset(
            key=in_data["key"],
            url=in_data["url"],
            time=in_data["time"],
            indiantime=in_data["indiantime"],
            file_name=in_data["file_name"],
            file_hash=in_data["file_hash"],
            idx=in_data["idx"],
            master_key=in_data["master_key"],
            master_url=in_data["master_url"],
            role=in_data["role"],
            scope=scope,
            zero_pub=in_data["zero_pub"],
            flt_account_parent_pub=in_data["flt_account_parent_pub"],
            flt_account_parent_idx=in_data["flt_account_parent_idx"],
            child_zero_pub=in_data["child_zero_pub"]
    )

    logging.info(f"Create asset transaction {asset}")
    payload = payload_pb2.TransactionPayload(
        payload_type=payload_pb2.TransactionPayload.CREATE_ASSET,
        create_asset=asset)

    return make_header_and_batch(
        payload=payload,
        inputs=inputs,
        outputs=outputs,
        txn_key=in_data["txn_key"],
        batch_key=in_data["batch_key"])
