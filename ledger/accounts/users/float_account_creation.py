


from sawtooth_sdk.processor.exceptions import InvalidTransaction
import coloredlogs, logging
coloredlogs.install()
import hashlib
from ledger import signatures

def handle_float_account_creation(float_account, header, state):
    """Handles creating an Account.

    Args:
        float__account (CreateFloatAccount): The transaction.
        header (TransactionHeader): The header of the Transaction.
        state (MarketplaceState): The wrapper around the Context.

    Raises:
        InvalidTransaction
            - The public key already exists for an Account.
    """
    if state.get_flt_account(header.signer_public_key,
                            float_account.parent_idx):
        raise InvalidTransaction("Float Account with public key {} already "
                                 "exists".format(header.signer_public_key))

    logging.info("No float account exists for {}".format(header.signer_public_key))

    if not state.get_organization(public_key=float_account.parent_zero_pub):
            logging.error("Parent with public key {}\
                            doesnt exists".format(float_account.parent_zero_pub))
            raise InvalidTransaction("Parent with public key {}\
                            doesnt exists".format(float_account.parent_zero_pub))


    if float_account.child_zero_pub:
        logging.info("Float account being created by CHILD")
        if not state.get_child(public_key=float_account.child_zero_pub,
                                        index=0):
            raise InvalidTransaction("THe child for orgnisation {} doesnt\
                    exists on the with public_key{} at index {} with orgs zeroth \
                    public key {}".format(float_account.org_name,\
                    float_account.child_zero_pub, 0,\
                    float_account.parent_zero_pub))

    ##check hash of the nonce

    if float_account.nonce_hash != hashlib.sha224(str(float_account.nonce).encode()).hexdigest():
            raise InvalidTransaction("Nonce hash {} doesnt match with hash of the nonce {}\
                    ".format(float_account.nonce_hash, float_account.nonce))

    ##checking the signatures whether the parent actually created this transaction
    if not signatures.ecdsa_signature_verify(float_account.parent_zero_pub,
                                float_account.signed_nonce,
                                float_account.nonce):
            raise InvalidTransaction("Signatures with account parent_pub \
                            coudnt be verified")
    else:
        logging.info("Signatures verified")

    try:
        state.set_float_account(
            public_key=header.signer_public_key,
            payload=float_account
            )

    except Exception as e:
        raise InvalidTransaction("Account with public key {} \
        has error in registration fields {}".format(header.signer_public_key, e))
