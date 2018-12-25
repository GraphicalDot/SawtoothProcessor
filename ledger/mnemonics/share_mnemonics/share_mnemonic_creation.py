


from sawtooth_sdk.processor.exceptions import InvalidTransaction
import coloredlogs, logging
coloredlogs.install()
import hashlib
from ledger import signatures

def create_share_mnemonic(payload, header, state):


    user_account = state.get_user(payload.user_address)
    #check whether who is floatin shared_mnemonic transactions are actually exists
    ##on the blockchain.
    if not user_account:
        raise InvalidTransaction("User Account with public key {} dont exists "
                                 "exists".format(header.signer_public_key))

    logging.info("THis is the user account {}".format(user_account))
        
    try:
        state.shared_mnemonic_transaction(
            public_key=header.signer_public_key,
            payload=payload,
            account=user_account
            )

    except Exception as e:
        raise InvalidTransaction("Errro while executing create_share_secret\
            {}".format(e))
