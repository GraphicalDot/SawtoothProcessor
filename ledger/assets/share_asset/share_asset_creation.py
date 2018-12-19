
from sawtooth_sdk.processor.exceptions import InvalidTransaction
import coloredlogs, logging
coloredlogs.install()
from  addressing import addresser
from ledger import signatures

def handle_share_asset(share_asset, header, state):
    """Handles creating an Asset.

    Args:
        transfer_asset (TransferAsset): The transaction payload
        header (TransactionHeader): The header of the Transaction.
        state (MarketplaceState): The wrapper around the context.

    Raises:
        InvalidTransaction
            - The name already exists for an Asset.
            - The txn signer has an account

    """

    logging.info("handle shared asset function execution is starting")
    asset = state.asset_at_address(share_asset.original_asset_address)

    issuer_account = state.account_at_address(share_asset.issuer_account_address)

    if not signatures.ecdsa_signature_verify(asset.public,
                            share_asset.asset_signature,
                            share_asset.nonce):
        raise InvalidTransaction("Signatures with asset public key coudnt be verified")
    else:
        logging.info("Asset signature for the issuer has been verified")


    if not signatures.ecdsa_signature_verify(issuer_account.public,
                            share_asset.account_signature,
                            share_asset.nonce):
        raise InvalidTransaction("Signatures with account public key coudnt be verified")
    else:
        logging.info("Account signature for the issuer has been verified")


    try:
        logging.info(share_asset)
        state.share_asset(share_asset, header.signer_public_key)
    except Exception as e:
        raise InvalidTransaction("share asset between {}\
                    to {} \
                    failed with an  error <<{}>>"\
                    .format(share_asset.original_asset_address, \
                    share_asset.issuer_account_address, e))
