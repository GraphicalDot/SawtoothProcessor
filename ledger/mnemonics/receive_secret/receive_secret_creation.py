


from sawtooth_sdk.processor.exceptions import InvalidTransaction
import coloredlogs, logging
coloredlogs.install()
import hashlib
from ledger import signatures
from addressing import addresser

from protocompiled import receive_secret_pb2
def empty_receive_secret():
    return receive_secret_pb2.ReceiveSecret()


def create_receive_secret(payload, header, state):

    logging.info(payload)
    user_account = state.get_user(payload.requester_address)
    if not user_account:
        raise InvalidTransaction("User Account with public key {} dont exists "
                                 "exists".format(payload.requester_address))



    if not signatures.ecdsa_signature_verify(user_account.public,
                            payload.signed_nonce,
                            payload.nonce):
        raise InvalidTransaction("Signatures with account public key coudnt be verified")
    else:
        logging.info("Signatures verified")




    try:

        state.update_receive_secret_array(
                                payload.requester_address,
                                user_account,
                                payload.idx)

        state.create_receive_secret(header.signer_public_key, payload)
    except Exception as e:
        raise InvalidTransaction("Errro while executing create_share_secret\
            {}".format(e))




class ReceiveSecretState(object):

    def __init__(self, context, timeout=2):
        self._context = context
        self._timeout = timeout
        self._state_entries = []

    def update_receive_secret_array(self, address, account, index):
        if index in account.receive_secret_idxs:
            raise InvalidTransaction("Duplicacy in recieve_secret_array of user")

        account.receive_secret_idxs.append(index)
        print ("User account {}".format(account))
        return self._context.set_state(
            {address: account.SerializeToString()}, self._timeout)

    def get_receive_secret(self, address):

        entries = self._context.get_state(
            addresses=[address],
            timeout=self._timeout)

        try:
            entry = entries[0]
        except Exception as e:
            logging.info("No RECEIVE_SECRET with address {} can be \
                        found".format(address))
            return False

        _receive_secret = empty_receive_secret()
        _receive_secret.ParseFromString(entry.data)
        return _receive_secret


    def create_receive_secret(self, public, payload):
        receive_secret_addr = addresser.receive_secret_address(public, payload.idx)
        if self.get_receive_secret(receive_secret_addr):
            raise InvalidTransaction("Receive_secret addr already present \
                            {}".format(receive_secret_addr))


        _receive_secret = empty_receive_secret()
        _receive_secret.role = payload.role
        _receive_secret.active = payload.active
        _receive_secret.created_on = payload.created_on
        _receive_secret.nonce = payload.nonce
        _receive_secret.nonce_hash = payload.nonce_hash
        _receive_secret.signed_nonce = payload.signed_nonce
        _receive_secret.idx = payload.idx
        _receive_secret.public = public

        return self._context.set_state(
            {receive_secret_addr: _receive_secret.SerializeToString()},
                self._timeout)
