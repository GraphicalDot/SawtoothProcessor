


from sawtooth_sdk.processor.exceptions import InvalidTransaction
import coloredlogs, logging
coloredlogs.install()
import hashlib
from ledger import signatures

def user_creation(user, header, state):

    if state.get_user(header.signer_public_key):
        raise InvalidTransaction("User Account with public key {} already "
                                 "exists".format(header.signer_public_key))

    try:
        state.set_user(
            public_key=header.signer_public_key,
            payload=user
            )

    except Exception as e:
        raise InvalidTransaction("User Account with public key {} \
        has error in registration fields {}".format(header.signer_public_key, e))
