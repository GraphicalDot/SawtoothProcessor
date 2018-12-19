
from sawtooth_sdk.processor.exceptions import InvalidTransaction
import coloredlogs, logging
coloredlogs.install()
from  addressing import addresser
from ledger import signatures

def handle_transfer_asset(transfer_asset, header, state):
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

    logging.info("handle transfer asset function execution is starting")

    if not signatures.ecdsa_signature_verify(transfer_asset.issuer_zero_pub,
                            transfer_asset.signed_nonce,
                            transfer_asset.nonce):
        raise InvalidTransaction("Signatures with account public key coudnt be verified")
    else:
        logging.info("Signatures verified")

    issuer_asset = state.asset_at_address(transfer_asset.issuer_address)
    receiver_asset = state.asset_at_address(transfer_asset.receiver_address)


    try:
        logging.info(transfer_asset)
        state.transfer_assets(transfer_asset, header.signer_public_key)
    except Exception as e:
        raise InvalidTransaction("Transfer asset between {}\
                    and receiver address{} \
                    failed with an  error <<{}>>"\
                    .format(transfer_asset.issuer_address, transfer_asset.receiver_address, e ))
