


from sawtooth_sdk.processor.exceptions import InvalidTransaction
import coloredlogs, logging
coloredlogs.install()
import hashlib
from ledger import signatures
from addressing import addresser
from ledger.mnemonics.share_mnemonics import share_mnemonic_state

def create_execute_shares(payload, header, state):

    ##user weho was the owner of this shared_secret_address contract
    user_account = state.get_user(header.signer_public_key)
    if not user_account:
        raise InvalidTransaction("User Account with public key {} dont exists "
                                 "exists".format(header.signer_public_key))


    ##this will verify that this user is actually the owner who is sending
    ##this transaction, to updaet the secret with new key
    if not signatures.ecdsa_signature_verify(header.signer_public_key,
                            payload.signed_nonce,
                            payload.nonce):
        raise InvalidTransaction("Signatures with account public key coudnt be verified")
    else:
        logging.info("Signatures verified")


    mnemonic_state = share_mnemonic_state.MnemonicState(context=state._context, timeout=3)
    share_mnemonic = mnemonic_state.get_share_mnemonic(payload.shared_secret_address)

    user_address = addresser.user_address(header.signer_public_key, 0)

    if share_mnemonic.ownership !=user_address:
        raise InvalidTransaction("This share secret contract is not owned by this user")

    try:
            mnemonic_state.update_secret(payload)


    except Exception as e:
        raise InvalidTransaction("Errro while executing create_share_secret\
            {}".format(e))
