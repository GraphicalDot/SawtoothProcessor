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
from protocompiled import account_pb2
from protocompiled import asset_pb2
from protocompiled import float_account_pb2
from sawtooth_sdk.processor.exceptions import InvalidTransaction
import base64
import traceback
import time
import coloredlogs, logging
coloredlogs.install()
#from marketplace_processor.protobuf import holding_pb2
#from marketplace_processor.protobuf import asset_pb2
#from marketplace_processor.protobuf import offer_pb2
#from marketplace_processor.protobuf import offer_history_pb2
#from marketplace_processor.protobuf import rule_pb2


#OFFER_RULES = [rule_pb2.Rule.EXCHANGE_ONCE_PER_ACCOUNT,
#               rule_pb2.Rule.EXCHANGE_ONCE,
#               rule_pb2.Rule.EXCHANGE_LIMITED_TO_ACCOUNTS]


def create_empty_account():
    return account_pb2.Account()


def create_empty_asset():
    return asset_pb2.Asset()



def create_empty_share_asset():
    return asset_pb2.ShareAsset()



def create_empty_float_account():
    return float_account_pb2.FloatAccount()

def create_empty_sig():
    return asset_pb2.Signatures()


class MarketplaceState(object):

    def __init__(self, context, timeout=2):
        self._context = context
        self._timeout = timeout
        self._state_entries = []

    def get_account(self, public_key):
        try:
            logging.info("Public Key {}  from get_account".format(public_key))
            address = addresser.create_account_address(account_id=public_key,
                                        index=0)
            logging.info("Account address in get_account is {}".format(address))
        except Exception as e:
            logging.error(e)
            raise InvalidTransaction("get_account error =={}".format(e))

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
            logging.info("No account with address {} and publickey {} can be \
                        found".format(address, public_key))
            return False

        account = create_empty_account()
        account.ParseFromString(entry.data)
        logging.info("This is the account at {} stored on blockchain \
                                {}".format(address, account))
        return account


    def account_at_address(self, address):

        entries = self._context.get_state(
            addresses=[address],
            timeout=self._timeout)
        try:
            entry = entries[0]
        except Exception as e:
            logging.info("No account with address  {} and public_key can be found\
                                {}".format(address, public_key))
            return False

        account = create_empty_account()
        account.ParseFromString(entry.data)
        logging.info("This is the account at {} stored on blockchain {}\
                        ".format(address, account))
        return account

    def set_float_account_idxs(self, public_key, key_index):
        account = self.get_account(public_key)

        address = addresser.create_account_address(account_id=public_key,
                index=0)

        if key_index in account.float_account_idxs:
            raise InvalidTransaction("Key index is already present in float_account_idxs")


        account.float_account_idxs.append(key_index)

        self._context.set_state(
            {address: account.SerializeToString()}, self._timeout)
        return



    def set_float_account(self, **input_data):
        """
        parent_pub=header.signer_public_key,
        pancard=float_account.pancard,
        phone_number=float_account.phone_number,
        email=float_account.email,
        claimed=float_account.claimed,
        claimed_by=float_account.claimed_by,
        create_asset_index=create_asset_index.float_account,
        parent_idx=float_account.parent_idx,
        time=float_account.time, //when this float account transaction was created
        indian_time=float_account.indian_time,
        claimed_on=float_account.claimed_on,
        parent_role=float_account.parent_role,
        user_role=float_account.user_role
        """

        logging.info("Paylaod from set_float_account {}".format(input_data))
        if input_data["parent_role"] != "ADMIN":
            ##change idx in the account present at public key input_data["parent_zero_pub"]
            self.set_float_account_idxs(input_data["parent_zero_pub"],
                    input_data["parent_idx"])

        ##here the parent pub is the nth index key of the parent on thich
        ##this float account address is generated
        address = addresser.float_account_address(account_id=input_data["parent_pub"],
                                    index=input_data["parent_idx"])
        float_account = create_empty_float_account()

        logging.info("This is the value of create_asset_idxs \
                        {}".format(input_data['create_asset_idxs']))
        float_account.pancard=input_data["pancard"]
        float_account.phone_number=input_data["phone_number"]
        float_account.email=input_data["email"]
        float_account.claimed=input_data["claimed"]
        float_account.claimed_by=input_data["claimed_by"]

        ##this is not required because create_asset_idxs will wlays be empty
        ##when intilizing float_account
        #float_account.create_asset_idxs=input_data["create_asset_idxs"]
        float_account.parent_idx=input_data["parent_idx"]
        float_account.time=input_data["time"]
        float_account.indian_time=input_data["indian_time"]
        float_account.claimed_on=input_data["claimed_on"]
        float_account.parent_pub=input_data["parent_pub"]
        float_account.parent_role=input_data["parent_role"]
        float_account.user_role=input_data["user_role"]
        logging.info(float_account)
        logging.info("Account after serialization %s", float_account.SerializeToString())
        return self._context.set_state(
                {address: float_account.SerializeToString()}, self._timeout)

    def get_flt_account(self, public_key, index):
        address = addresser.float_account_address(account_id=public_key,
                                                index=index)
        ##entries will be a weird list of the form
        ##[address: "318c9fa5d39e9ccd2769115795e384b8e83b3267172ae518136ac49ddc5adf71d87814"
        ##data: "\nB02dbf0f4a3defef38df754122ef7c10fee6a4bb363312367524f86d230e205d459\022$b6de5d5b-7870-49df-971e-0885986bfa96\032
        ##\006seller\"\021978-0-9956537-6-4*\0161-191-790-04532\r1-932866-82-5:\001\000"]

        entries = self._context.get_state(
            addresses=[address],
            timeout=self._timeout)

        try:
            entry = entries[0]
            logging.info("float_account data corresponding to \
                            {} is {}".format(address, entry))
        except Exception as e:
            logging.info("float_account data corresponding to \
                            {} is {}".format(address, None))
            return False

        float_account = create_empty_float_account()
        float_account.ParseFromString(entry.data)
        logging.info("This is the float_account stored on blockchain \
                    {}".format(float_account))
        return float_account


    def claim_float_account(self, public_key, parent_idx, claimed_by, claimed_on):
        """
        Make claimed_on as the time sent by the transaction and claimed_by as
        the zeroth index key of the user.
        THen update the float_account address
        """
        float_account = self.get_flt_account(public_key, parent_idx)
        float_account.claimed = True
        float_account.claimed_by = claimed_by
        float_account.claimed_on = claimed_on
        address = addresser.float_account_address(public_key,
                                    parent_idx)

        self._context.set_state(
            {address: float_account.SerializeToString()}, self._timeout)
        return




    def set_account(self, public_key, account_payload):
        if "" in [account_payload.role, account_payload.adhaar,
            account_payload.phone_number, account_payload.pancard,
            account_payload.organization_name]:
            raise InvalidTransaction('shouldnt be left empty')

        logging.info("Entered into set_Account with parent pub %s"%account_payload.parent_pub)
        address = addresser.create_account_address(account_id=public_key,
                        index=0)

        logging.info("THis is the accoutn address {}".format(address))
        self.claim_float_account(account_payload.parent_pub, account_payload.parent_idx,
                    public_key,
                    account_payload.indian_time)

        logging.info("Float account has been claimed ")


        #container = _get_account_container(self._state_entries, address)

        account = create_empty_account()
        account.public = public_key
        account.parent_zero_pub = account_payload.parent_zero_pub
        account.user_id = account_payload.user_id
        account.adhaar = account_payload.adhaar
        account.phone_number = account_payload.phone_number
        account.pancard = account_payload.pancard
        account.first_name = account_payload.first_name
        account.last_name = account_payload.last_name
        account.organization_name = account_payload.organization_name
        account.email = account_payload.email
        account.time = account_payload.time
        account.indian_time = account_payload.indian_time
        account.deactivate = account_payload.deactivate
        account.deactivate_on = account_payload.deactivate_on
        account.last_active = account_payload.last_active

        account.role = account_payload.role
        account.parent_role = account_payload.parent_role


        if account_payload.create_asset_idxs:
            account.create_asset_idxs.extend(account_payload.create_asset_idxs)


        logging.info(account)
        logging.info("Account after serialization %s", account.SerializeToString())
        return self._context.set_state(
            {address: account.SerializeToString()}, self._timeout)


    def set_index_account(self, public_key, key_index):
        address = addresser.make_account_address(account_id=public_key)

        account = self.get_account(public_key)
        if  int(key_index) in account.key_index:
            raise InvalidTransaction("Keys from childkeyindex is already in use")

        account.key_index.append(int(key_index))
        logging.info("Account after appending key_index %s"%account)

        try:
            self._context.set_state({address: account.SerializeToString()},
                                    self._timeout)
        except Exception as e:
            logging.info(e)
            traceback.print_exc()
            raise Exception()
        return

    def asset_at_address(self, address):
        """
        Get asset data at address

        """
        entries = self._context.get_state(
            addresses=[address],
            timeout=self._timeout)
        try:
            entry = entries[0]
        except Exception as e:
            logging.info("No account with address {} and publickey {} \
                                can be found".format(address, public_key))
            return False

        asset = create_empty_asset()
        asset.ParseFromString(entry.data)
        logging.info("This is the asset at {} stored on blockchain {}"\
                            .format(asset, address))
        return asset


    def get_asset(self, asset_id, index):
        address = addresser.create_asset_address(asset_id=asset_id, index=index)
        """

        self._state_entries.extend(self._context.get_state(
            addresses=[address],
            timeout=self._timeout))

        return self._get_asset(address=address, name=name)
        """
        asset = self._context.get_state(
            addresses=[address],
            timeout=self._timeout)
        return asset




    def update_asset_index(self, address, account, key_index):
        if  int(key_index) in account.create_asset_idxs:
            raise InvalidTransaction("Keys from childkeyindex is already in use")

        account.create_asset_idxs.append(int(key_index))
        logging.info("Account after appending key_index %s"%account)

        try:
            self._context.set_state({address: account.SerializeToString()},
                                    self._timeout)
            logging.info("Float account has been updated")
        except Exception as e:
            logging.info(e)
            traceback.print_exc()
            raise Exception()
        return

    def set_asset(self, payload, public, account, account_type):
        """
        payload will have the CreateAsset in the payload
        public: hex public key with whose private key transaction was signed
        account: could be a float account or account
        account_type: could be FLOAT_ACCOUNT or CREATE_ACCOUNT
        """
        logging.info("Account  in set_asset <<{}>>".format(account))
        if account_type == "FLOAT_ACCOUNT":
            account_address = addresser.float_account_address(
                    account_id=payload.flt_account_parent_pub,
                    index=payload.flt_account_parent_idx
            )
        else:
            account_address = addresser.create_account_address(
                    account_id=payload.zero_pub, index=0
            )

        self.update_asset_index(account_address, account, payload.idx)

        address = addresser.create_asset_address(
                                asset_id=public,
                                index=payload.idx)

        asset = create_empty_asset()

        asset.key = payload.key
        asset.url = payload.url
        asset.time = payload.time
        asset.indiantime = payload.indiantime
        asset.file_name= payload.file_name
        asset.file_hash=payload.file_hash
        asset.idx = payload.idx
        asset.master_key=payload.master_key
        asset.master_url=payload.master_url
        asset.role = payload.role
        asset.public = public

        if payload.scope:
            asset.scope.cert_type = payload.scope.cert_type
            asset.scope.product_type = payload.scope.product_type
            asset.scope.product_name = payload.scope.product_name


        logging.info(asset)
        logging.info("Account after serialization %s", asset.SerializeToString())
        return self._context.set_state(
            {address: asset.SerializeToString()}, self._timeout)

    def transfer_assets(self, payload, public):

        issuer_account_address = addresser.create_account_address(
                    account_id=payload.issuer_zero_pub,
                    index=0
        )

        issuer_asset = self.asset_at_address(payload.issuer_address)
        issuer_asset.ownership_transfer = payload.receiver_address
        issuer_asset.transferred_on = payload.indiantime

        receiver_asset = self.asset_at_address(payload.receiver_address)
        receiver_asset.key = payload.key
        receiver_asset.url = payload.url
        receiver_asset.file_name= payload.file_name
        receiver_asset.file_hash=payload.file_hash
        receiver_asset.master_key=payload.master_key
        receiver_asset.master_url=payload.master_url

        if payload.scope:
            receiver_asset.scope.cert_type = payload.scope.cert_type
            receiver_asset.scope.product_type = payload.scope.product_type
            receiver_asset.scope.product_name = payload.scope.product_name

        """
        signature_list = []
        if payload.signatures:
            sig = create_empty_sig()
            for signature in payload.signatures:
                sig.ParseFromString(signature.encode())
            signature_list.append(sig)

        receiver_asset.authenticity_signatures = signature_list
        """
        receiver_asset.ownership_received = payload.issuer_address
        receiver_asset.received_on= payload.indiantime
        receiver_asset.parent_address = issuer_account_address

        self._context.set_state(
            {payload.issuer_address: issuer_asset.SerializeToString()}, self._timeout)

        self._context.set_state(
            {payload.receiver_address: receiver_asset.SerializeToString()}, self._timeout)
        return


    def share_asset(self, payload, public):
        ##original asset shared_with key must be appended with the new random index
        ##at which this shared_asset has been created, so if original asset is revoked
        ## all the shared_assets will be revoked as well by iterating over the
        ## shared_with keys
        original_asset = self.asset_at_address(payload.original_asset_address)
        original_asset.shared_with.append(payload.idx)
        self._context.set_state(
            {payload.original_asset_address: original_asset.SerializeToString()}, self._timeout)


        share_asset_address = addresser.share_asset_address(
                            public,  payload.idx)


        share_asset = create_empty_share_asset()
        share_asset.key = payload.key
        share_asset.time = payload.time
        share_asset.url = payload.url
        share_asset.indiantime = payload.indiantime
        share_asset.file_name= payload.file_name
        share_asset.file_hash=payload.file_hash
        share_asset.idx = payload.idx
        share_asset.master_key=payload.master_key
        share_asset.master_url=payload.master_url
        share_asset.role = payload.role
        share_asset.pancard = payload.pancard
        share_asset.adhaar = payload.adhaar
        share_asset.phone_number = payload.phone_number
        share_asset.email = payload.email
        share_asset.idx = payload.idx
        share_asset.account_signature = payload.account_signature
        share_asset.asset_signature = payload.asset_signature
        share_asset.nonce = payload.nonce
        share_asset.issuer_account_address = payload.issuer_account_address
        share_asset.receiver_account_address = payload.receiver_account_address
        share_asset.public = public
        share_asset.revoked_on = payload.revoked_on

        if payload.scope:
            share_asset.scope.cert_type = payload.scope.cert_type
            share_asset.scope.product_type = payload.scope.product_type
            share_asset.scope.product_name = payload.scope.product_name

        if payload.authenticity_signatures:
            for signature in payload.signatures:
                sig = create_empty_sig()
                sig.ParseFromString(signature.encode())
                share_asset.authenticity_signatures.append(sig)


        logging.info(share_asset)
        logging.info("share_asset after serialization %s", share_asset.SerializeToString())

        self._context.set_state(
            {share_asset_address: share_asset.SerializeToString()}, self._timeout)
        return
