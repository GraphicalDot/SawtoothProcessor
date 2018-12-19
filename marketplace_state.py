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
from protocompiled import organization_account_pb2
from protocompiled import asset_pb2
#from protocompiled import float_account_pb2
from protocompiled import child_account_pb2
from protocompiled import receive_asset_pb2
from protocompiled import share_asset_pb2
from protocompiled import user_pb2
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


def create_empty_organization():
    return organization_account_pb2.OrganizationAccount()



def create_empty_child():
    return child_account_pb2.ChildAccount()


def create_empty_asset():
    return asset_pb2.Asset()

def empty_receive_asset():
    return receive_asset_pb2.ReceiveAsset()

def create_empty_share_asset():
    return share_asset_pb2.ShareAsset()



def create_empty_float_account():
    return float_account_pb2.FloatAccount()

def empty_user():
    return user_pb2.UserAccount()


def create_empty_sig():
    return asset_pb2.Signatures()


class MarketplaceState(object):

    def __init__(self, context, timeout=2):
        self._context = context
        self._timeout = timeout
        self._state_entries = []



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


    def get_user(self, public_key):
        try:
            address = addresser.user_address(
                                        account_id=public_key,
                                        index=0)
        except Exception as e:
            logging.error(e)
            raise InvalidTransaction("get_user error =={}".format(e))

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
    def get_organization(self, public_key):
        try:
            address = addresser.organization_address(
                                        public=public_key,
                                        index=0)
            logging.info("Organization Account address in get_account is {}".format(address))
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

        logging.info("ENtries correspoding to account address \
                {} are {}".format(address, entries))
        try:
            entry = entries[0]
        except Exception as e:
            logging.info("No organization account with address {} and publickey {} can be \
                        found".format(address, public_key))
            return False

        account = create_empty_organization()
        account.ParseFromString(entry.data)
        logging.info("This is the account at {} stored on blockchain \
                                {}".format(address, account))
        return account

    def set_organization(self, public_key, account_payload):
        logging.info(account_payload)
        if "" in [
            account_payload.gst_number, account_payload.pancard,
            account_payload.org_name]:
            raise InvalidTransaction('shouldnt be left empty')

        logging.info("Entered into set_Account with parent pub %s"%account_payload.parent_pub)
        address = addresser.organization_address(
                                        public=public_key, index=0)

        logging.info("THis is the orgnization address {}".format(address))

        if account_payload.role != "ADMIN":
            #since ADMIN organization accoutn doest have a float_account transaction
            ## there is no need to claim float_account
            self.claim_float_account(account_payload.parent_pub, account_payload.parent_idx,
                    public_key,
                    account_payload.indian_time)

            logging.info("Float account has been claimed ")


        #container = _get_account_container(self._state_entries, address)

        organization = create_empty_organization()
        organization.public = public_key
        organization.parent_zero_pub = account_payload.parent_zero_pub
        organization.user_id = account_payload.user_id
        organization.phone_number = account_payload.phone_number
        organization.pancard = account_payload.pancard
        organization.gst_number = account_payload.gst_number
        organization.tan_number = account_payload.tan_number
        organization.org_name = account_payload.org_name
        organization.email = account_payload.email
        organization.time = account_payload.time
        organization.indian_time = account_payload.indian_time
        organization.deactivate = account_payload.deactivate
        organization.deactivate_on = account_payload.deactivate_on

        organization.role = account_payload.role
        organization.parent_role = account_payload.parent_role
        organization.float_account_address= account_payload.float_account_address


        if account_payload.create_asset_idxs:
            organization.create_asset_idxs.extend(account_payload.create_asset_idxs)


        logging.info(organization)
        logging.info("Orgnization after serialization %s", organization.SerializeToString())
        return self._context.set_state(
            {address: organization.SerializeToString()}, self._timeout)


    def set_organization_children(self, public_key, key_index):
        account = self.get_organization(public_key)
        address = addresser.create_organization_account_address(
                account_id=public_key,
                index=0)

        if key_index in account.child_account_idxs:
            raise InvalidTransaction("Key index is already present in \
                    child_account_idxs")


        account.child_account_idxs.append(key_index)

        self._context.set_state(
            {address: account.SerializeToString()}, self._timeout)
        logging.info("Account at address {} and public_key{} appended with \
                key index {}".format(address, public_key, key_index))
        return


    def get_child(self, public_key, index):
        try:
            address = addresser.child_account_address(
                                        account_id=public_key,
                                        index=0)
            logging.info("Child address in get_account is {}".format(address))
        except Exception as e:
            logging.error(e)
            raise InvalidTransaction("get_child error =={}".format(e))

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

        account = create_empty_child()
        account.ParseFromString(entry.data)
        logging.info("This is the account at {} stored on blockchain \
                                {}".format(address, account))
        return account




    def set_child(self, public_key, payload):
        logging.info(type(payload))
        logging.info(dir(payload))
        self.set_organization_children(payload.parent_zero_pub, payload.parent_idx)


        address = addresser.child_account_address(public_key, 0)
        child_account = create_empty_child()

        child_account.parent_idx=payload.parent_idx
        child_account.parent_zero_pub=payload.parent_zero_pub
        child_account.parent_role=payload.parent_role


        child_account.first_name = payload.first_name
        child_account.last_name = payload.last_name


        child_account.org_name=payload.org_name
        child_account.user_id = payload.user_id
        child_account.pancard=payload.pancard
        child_account.gst_number=payload.gst_number
        child_account.tan_number=payload.tan_number
        child_account.phone_number=payload.phone_number
        child_account.email=payload.email
        ##this was required to check the signed_nonce signed by the zeroth private
        ##key of the creator
        child_account.time=payload.time
        child_account.indian_time=payload.indian_time

        child_account.role=payload.role
        child_account.public = public_key

        child_account.deactivate = payload.deactivate
        child_account.deactivate_on = payload.deactivate_on
        ##so that we can later check who actually made this float_account and
        ## and was a vald account
        child_account.nonce = payload.nonce
        child_account.nonce_hash = payload.nonce_hash
        child_account.signed_nonce = payload.signed_nonce

        logging.info(child_account)

        logging.info("Account after serialization %s", child_account.SerializeToString())
        return self._context.set_state(
                {address: child_account.SerializeToString()}, self._timeout)




    ##This changes the float_account_inds of the orgnisation account present
    ##at the public_key
    def set_org_float_account_idxs(self, public_key, key_index):
        account = self.get_organization(public_key)

        address = addresser.create_organization_account_address(
                account_id=public_key,
                index=0)

        if key_index in account.float_account_idxs:
            raise InvalidTransaction("Key index is already present in float_account_idxs")


        account.float_account_idxs.append(key_index)

        self._context.set_state(
            {address: account.SerializeToString()}, self._timeout)
        return


    ##This changes the float_account_inds of the orgnisation account present
    ##at the public_key
    def set_child_float_account_idxs(self, public_key, key_index):
        child_account = self.get_child(public_key, 0)

        address = addresser.child_account_address(account_id=public_key,
                index=0)

        if key_index in child_account.float_account_idxs:
            raise InvalidTransaction("Key index is already present in float_account_idxs")


        child_account.float_account_idxs.append(key_index)

        self._context.set_state(
            {address: child_account.SerializeToString()}, self._timeout)
        return



    def set_float_account(self, public_key, payload):

        logging.info("Paylaod from set_float_account {}".format(payload))

        ##change idx in the account present at public key input_data["parent_zero_pub"]
        self.set_org_float_account_idxs(payload.parent_zero_pub,
                    payload.parent_idx)

        ##this implies that this float account being created by the child of
        ##payload.parent_role
        if payload.child_zero_pub:
            self.set_child_float_account_idxs(payload.child_zero_pub,
                        payload.parent_idx)


        ##here the parent pub is the nth index key of the parent on thich
        ##this float account address is generated
        address = addresser.float_account_address(account_id=public_key,
                                    index=payload.parent_idx)

        float_account = create_empty_float_account()

        logging.info("This is the value of create_asset_idxs \
                        {}".format(payload.create_asset_idxs))
        float_account.pancard=payload.pancard
        float_account.phone_number=payload.phone_number
        float_account.email=payload.email
        float_account.gst_number=payload.gst_number
        float_account.tan_number=payload.tan_number
        float_account.org_name=payload.org_name

        ##will be changed when the person or orgnization claims this account
        float_account.claimed=payload.claimed
        float_account.claimed_by=payload.claimed_by
        float_account.claimed_on=payload.claimed_on

        ##this is not required because create_asset_idxs will wlays be empty
        ##when intilizing float_account
        #float_account.create_asset_idxs=input_data["create_asset_idxs"]
        float_account.time=payload.time
        float_account.indian_time=payload.indian_time

        ##parent_pub at random_idxs in float_account_idxs array with which this
        ##float account address was generated
        float_account.parent_idx=payload.parent_idx

        ##this was required to check the signed_nonce signed by the zeroth private
        ##key of the creator
        float_account.parent_zero_pub=payload.parent_zero_pub
        float_account.parent_role=payload.parent_role
        float_account.role=payload.role
        float_account.public = public_key

        ##so that we can track if its been made by a child of the organiation or not
        ##it will be an empty field if the organization themselves made the account
        float_account.child_zero_pub = payload.child_zero_pub
        float_account.parent_zero_pub = payload.parent_zero_pub

        ##so that we can later check who actually made this float_account and
        ## and was a vald account
        float_account.nonce = payload.nonce
        float_account.nonce_hash = payload.nonce_hash
        float_account.signed_nonce = payload.signed_nonce

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



    ##updating create_asset_idxs array present at the address with the key_index
    def update_asset_index(self, address, account, key_index):

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

    def update_receive_index(self, address, account, key_index):

        account.receive_asset_idxs.append(int(key_index))

        try:
            self._context.set_state({address: account.SerializeToString()},
                                    self._timeout)
            logging.info("Float account has been updated")
        except Exception as e:
            logging.info(e)
            traceback.print_exc()
            raise Exception()
        return

    def update_share_index(self, address, account, key_index):

        account.share_asset_idxs.append(int(key_index))

        try:
            self._context.set_state({address: account.SerializeToString()},
                                    self._timeout)
            logging.info("Float account has been updated")
        except Exception as e:
            logging.info(e)
            traceback.print_exc()
            raise Exception()
        return


    def set_asset(self, public, payload):
        """
        payload will have the CreateAsset in the payload
        public: hex public key with whose private key transaction was signed
        account: could be a float account or account
        account_type: could be FLOAT_ACCOUNT or CREATE_ACCOUNT
        """
        logging.info("Payload  in set_asset <<{}>>".format(payload))
        if payload.flt_account_parent_pub:
            account_address = addresser.float_account_address(
                    account_id=payload.flt_account_parent_pub,
                    index=payload.flt_account_parent_idx
            )
            logging.info("Updating create_asset_idxs in float_account\
                at {}".format(account_address))
            float_account = self.get_flt_account(
                    public_key=payload.flt_account_parent_pub,
                    index=payload.flt_account_parent_idx)
            self.update_asset_index(account_address, float_account, payload.idx)

        else:
            account_address = addresser.create_organization_account_address(
                    account_id=payload.zero_pub,
                    index=0
            )
            logging.info("Updating create_asset_idxs in \
                    organization_account at {}".format(account_address))
            organization_account = self.get_organization(
                            public_key=payload.zero_pub)

            self.update_asset_index(account_address, organization_account, payload.idx)

        ##if this is present that means that this asset is being created by child
        ##of the organization, so the payload.idx needs to be appended to the
        ##create_asset_idxs array of the child too
        if payload.child_zero_pub:
            account_address = addresser.child_account_address(account_id=payload.child_zero_pub,
                            index=0)

            child_account = self.get_child(payload.child_zero_pub, 0)
            self.update_asset_index(account_address, child_account, payload.idx)

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
        asset.expired_on=payload.expired_on
        asset.role = payload.role
        asset.public = public
        asset.child_zero_pub = payload.child_zero_pub
        if payload.scope:
            asset.scope.group = payload.scope.group
            asset.scope.sub_group = payload.scope.sub_group
            asset.scope.field = payload.scope.field
            asset.scope.nature = payload.scope.nature
            asset.scope.operations = payload.scope.operations
            asset.scope.description = payload.scope.description


        logging.info(asset)
        logging.info("Account after serialization %s", asset.SerializeToString())
        return self._context.set_state(
            {address: asset.SerializeToString()}, self._timeout)

    def transfer_assets(self, payload, public):

        issuer_account_address = addresser.create_organization_account_address(
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
        receiver_asset.issuer_child_zero_pub=payload.issuer_child_zero_pub
        if payload.scope:
            receiver_asset.scope.group = payload.scope.group
            receiver_asset.scope.sub_group = payload.scope.sub_group
            receiver_asset.scope.field = payload.scope.field
            receiver_asset.scope.nature = payload.scope.nature
            receiver_asset.scope.operations = payload.scope.operations
            receiver_asset.scope.description = payload.scope.description

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

    def receive_asset(self, public, org_account, child_address,
                            child_account, payload):

        self.update_receive_index(payload.org_address,
                                org_account,
                                payload.idx)
        if payload.child_zero_pub:
            self.update_receive_index(child_address,
                        child_account,
                        payload.idx)

        address = addresser.receive_asset_address(
                asset_id=public,
                index=payload.idx)
        receive_asset =empty_receive_asset()

        receive_asset._id_ = payload._id_
        receive_asset.time = payload.time
        receive_asset.indiantime= payload.indiantime
        receive_asset.idx=payload.idx
        receive_asset.at_which_asset_expires=payload.at_which_asset_expires
        receive_asset.org_address=payload.org_address
        receive_asset.org_role = payload.org_role
        receive_asset.org_name = payload.org_name
        receive_asset.child_zero_pub=payload.child_zero_pub
        receive_asset.nonce=payload.nonce
        receive_asset.signed_nonce=payload.signed_nonce
        receive_asset.nonce_hash=payload.nonce_hash
        receive_asset.unique_code_hash=payload.unique_code_hash
        receive_asset.encrypted_unique_code=payload.encrypted_unique_code
        receive_asset.encrypted_admin_unique_code=payload.encrypted_admin_unique_code
        receive_asset.public=public

        if payload.receive_asset_details:
            receive_asset.receive_asset_details.name = payload.receive_asset_details.name
            receive_asset.receive_asset_details.description = payload.receive_asset_details.description


        self._context.set_state(
            {address: receive_asset.SerializeToString()}, self._timeout)
        return

    def share_asset(self, payload, public):
        ##original asset shared_with key must be appended with the new random index
        ##at which this shared_asset has been created, so if original asset is revoked
        ## all the shared_assets will be revoked as well by iterating over the
        ## shared_with keys

        ##this will add the idx to the shared_with array of the asset
        original_asset = self.asset_at_address(payload.original_asset_address)
        original_asset.shared_with.append(payload.idx)
        self._context.set_state(
            {payload.original_asset_address: original_asset.SerializeToString()}, self._timeout)

        issuer_account = self.account_at_address(payload.issuer_account_address)
        self.update_share_index(payload.issuer_account_address,
                        issuer_account, payload.idx)

        ##if its been shared with a child append shared_asset_array of the child too
        if payload.child_zero_pub:
            child_address = addresser.child_account_address(
                                        payload.child_zero_pub, 0)
            child_account = self.get_child(payload.child_zero_pub, 0)
            child_account.share_asset_idxs.append(payload.idx)
            self._context.set_state(
                {child_address: child_account.SerializeToString()}, self._timeout)


        share_asset_address = addresser.share_asset_address(
                            public,  payload.idx)



        share_asset = create_empty_share_asset()
        share_asset.key = payload.key
        share_asset.time = payload.time
        share_asset.url = payload.url
        share_asset.master_key=payload.master_key
        share_asset.master_url=payload.master_url
        share_asset.indiantime = payload.indiantime
        share_asset.file_name= payload.file_name
        share_asset.file_hash=payload.file_hash
        share_asset.idx = payload.idx
        share_asset.account_signature = payload.account_signature
        share_asset.asset_signature = payload.asset_signature
        share_asset.nonce = payload.nonce
        share_asset.nonce_hash = payload.nonce_hash
        share_asset.to_org_name = payload.to_org_name
        share_asset.to_org_address= payload.to_org_address
        share_asset.public = public
        share_asset.revoked_on = payload.revoked_on
        share_asset.original_asset_address = payload.original_asset_address
        share_asset.issuer_account_address = payload.issuer_account_address
        share_asset.receive_asset_address = payload.receive_asset_address
        share_asset.child_zero_pub = payload.child_zero_pub
        share_asset.unique_code_hash=payload.unique_code_hash

        logging.info(share_asset)
        logging.info("share_asset after serialization %s", share_asset.SerializeToString())

        self._context.set_state(
            {share_asset_address: share_asset.SerializeToString()}, self._timeout)
        return
