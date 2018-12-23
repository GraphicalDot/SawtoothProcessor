


from sawtooth_sdk.processor.exceptions import InvalidTransaction
import coloredlogs, logging
coloredlogs.install()
import hashlib
from ledger import signatures
from ledger.mnemonics.share_mnemonics import share_mnemonic_state

def create_activate_shares(payload, header, state):


    admin_account = state.account_at_address(payload.admin_address)
    if not admin_account:
        raise InvalidTransaction("User Account with public key {} dont exists "
                                 "exists".format(header.signer_public_key))



    if not signatures.ecdsa_signature_verify(admin_account.public,
                            payload.signed_nonce,
                            payload.nonce):
        raise InvalidTransaction("Signatures with account public key coudnt be verified")
    else:
        logging.info("Signatures verified")




    try:

            mnemonic_state = share_mnemonic_state.MnemonicState(context=state._context, timeout=3)
            mnemonic_state.update_reset_key(payload)

    except Exception as e:
        raise InvalidTransaction("Errro while executing create_share_secret\
            {}".format(e))
