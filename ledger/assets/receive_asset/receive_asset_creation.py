
from sawtooth_sdk.processor.exceptions import InvalidTransaction
import coloredlogs, logging
coloredlogs.install()
from  addressing import addresser
from ledger import signatures

def handle_receive_asset(receive_asset, header, state):
    """Handles creating a Receive Asset Transaction.
    """

    logging.info("handle receive asset function execution is starting")

    if not signatures.ecdsa_signature_verify(receive_asset.org_zero_pub,
                            receive_asset.signed_nonce,
                            receive_asset.nonce):
        raise InvalidTransaction("Signatures with account public key coudnt be verified")
    else:
        logging.info("Signatures verified")


    ##users zeroth public key has signed this transaction
    org_account = state.get_organization(public_key=receive_asset.org_zero_pub)

    if not org_account:
        raise InvalidTransaction("Account with public key {}\
                                 doesnt exists".format(receive_asset.org_zero_pub))

    if receive_asset.idx in org_account.receive_asset_idxs:
        raise InvalidTransaction("This idx {} has already have been used in org\
                {}".format(receive_asset.idx, receive_asset.org_address))

    if receive_asset.child_zero_pub:
        child_account = state.get_child(public_key=receive_asset.child_zero_pub, index=0)
        if not child_account:
            raise InvalidTransaction("THe child for orgnisation {} doesnt\
                    exists on the with public_key{} at index {} with orgs zeroth \
                    public key {}".format(receive_asset.org_name,\
                    receive_asset.child_zero_pub, 0,\
                    receive_asset.org_zero_pub))
        if child_account.org_name != receive_asset.org_name:
            raise InvalidTransaction("Child org name and receive asset org name doesnt match")
        child_address = addresser.child_account_address(receive_asset.child_zero_pub, index=0)
    else:
        child_address=None
        child_account=None

    try:
        logging.info(receive_asset)
        state.receive_asset(header.signer_public_key, org_account, child_address,
                                child_account, receive_asset)
    except Exception as e:
        raise InvalidTransaction("Receive asset at index {}\
                    and with public key{} \
                    on an orgnization address <<{}>>"\
                    .format(receive_asset.idx, header.signer_public_key, receive_asset.org_address ))
