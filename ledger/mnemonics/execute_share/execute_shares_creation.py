


from sawtooth_sdk.processor.exceptions import InvalidTransaction
import coloredlogs, logging
coloredlogs.install()
import hashlib
from ledger import signatures
from addressing import addresser
#from ledger.mnemonics.share_mnemonics import share_mnemonic_state

def create_execute_shares(payload, header, state):

    ##user weho was the owner of this shared_secret_address contract
    ##TODO lots of things

    share_secret = state.get_share_secret(payload.share_secret_address)
    ##update implies whether the share_secret transaction needs to be updated
    ##or insert a new one altoghether
    if not share_secret:
        raise InvalidTransaction("Share secret {} dont exists\
                            ".format(payload.share_secret_address))



    receive_secret = state.get_receive_secret(share_secret.ownership)
    if not receive_secret:
        raise InvalidTransaction("RECEIVE_SECRET with address {} dont exists"\
                            .format(share_secret.ownership))


    state.check_nonce_hash(payload.nonce, payload.nonce_hash)
    ##this will verify that this user is actually the owner who is sending
    ##this transaction, to updaet the secret with new key
    if not signatures.ecdsa_signature_verify(receive_secret.public,
                            payload.signed_nonce,
                            payload.nonce):
        raise InvalidTransaction("Signatures with account public key coudnt be verified")
    else:
        logging.info("Signatures verified")

    try:
            state.update_reset_secret(
                        share_secret=share_secret,
                        payload=payload)


    except Exception as e:
        raise InvalidTransaction("Errro while executing create_share_secret\
            {}".format(e))
