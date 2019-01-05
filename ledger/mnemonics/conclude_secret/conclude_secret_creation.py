''


from sawtooth_sdk.processor.exceptions import InvalidTransaction
import coloredlogs, logging
coloredlogs.install()
import hashlib
from ledger import signatures
#from ledger.mnemonics. import share_mnemonic_state

def create_conclude_secret(payload, header, state):


    user_account = state.get_user(payload.user_address)
    if not user_account:
        raise InvalidTransaction("User Account with public key {} dont exists "
                                 "exists".format(header.signer_public_key))

    ##checkinf ig the nonce hash matched with nonce hash
    state.check_nonce_hash(payload.nonce, payload.nonce_hash)

    ##check of the signatures are valid one or not, the nonce was signed
    ##with the zeroth public key of the user account who wants to share the
    ##mnemonic
    state.check_signatures(user_account.public, payload.user_signed_nonce,
                                        payload.nonce)



    share_secret = state.get_share_secret(payload.share_secret_address)
    ##update implies whether the share_secret transaction needs to be updated
    ##or insert a new one altoghether
    if not share_secret:
        raise InvalidTransaction("Share secret {} dont exists\
                            ".format(payload.share_secret_address))

    state.check_signatures(share_secret.public, payload.signed_nonce,
                                        payload.nonce)



    try:

        state.conclude_secret(share_secret=share_secret,
                                payload=payload)
    except Exception as e:
        raise InvalidTransaction("Errro while executing create_ativate_secret\
            {}".format(e))
