


from sawtooth_sdk.processor.exceptions import InvalidTransaction
import coloredlogs, logging
coloredlogs.install()
import hashlib
from ledger import signatures
from protocompiled import share_secret_pb2

from addressing import addresser

def empty_share_secret():
    return share_secret_pb2.ShareSecret()


def create_share_secret(payload, header, state):
    logging.info(payload)
    user_account = state.get_user(payload.user_address)
    #check whether who is floatin shared_mnemonic transactions are actually exists
    ##on the blockchain.
    if not user_account:
        raise InvalidTransaction("User Account with public key {} dont exists "
                                 "exists".format(header.signer_public_key))

    logging.info("THis is the user account {}".format(user_account))

    ##check whether the receive_secret to which this secret will be shared
    ##actually exists or not
    receive_secret = state.get_receive_secret(payload.ownership)
    if not receive_secret:
        raise InvalidTransaction("receive secret with address  {} dont exists "
                                 "exists".format(payload.ownership))
    else:
        logging.info("THis is the receive secret {}".format(payload.ownership))

    ##check whether the share_secret transaction at the public key actually exists
    ##or not, if it exists cant be created again
    share_secret_address= addresser.shared_secret_address(
                                        header.signer_public_key,
                                        payload.idx)


    share_secret = state.get_share_secret(share_secret_address)
    ##update implies whether the share_secret transaction needs to be updated
    ##or insert a new one altoghether
    if share_secret:
        logging.info("share secret with address  {} already exists"\
                                 .format(share_secret_address))
        update=True
        logging.info("Existing share_secret transaction will be updated")
    else:
        update=False
        logging.info("New share_secret transaction will be created")

    ##checkinf ig the nonce hash matched with nonce hash
    state.check_nonce_hash(payload.nonce, payload.nonce_hash)

    ##check of the signatures are valid one or not, the nonce was signed
    ##with the zeroth public key of the user account who wants to share the
    ##mnemonic
    state.check_signatures(user_account.public, payload.signed_nonce,
                                        payload.nonce)



    try:
        ##this will puch the transaction on the ledger, A new SHARE_SECRET
        ##transaction, whose public key is generated from the random idx
        ##at user_address mnemonic
        state.create_share_secret(
            public=header.signer_public_key,
            payload=payload,
            share_secret_address=share_secret_address,
            update=update
            )

        ##now th share_secret_address must be appended to the users account
        ##share_secret_addresses array
        if not update:
            state.update_share_secret_addresses(address=payload.user_address,
                                account=user_account,
                                share_secret_address=share_secret_address)


    except Exception as e:
        raise InvalidTransaction("Errro while executing create_share_secret\
            {}".format(e))


class ShareSecretState(object):

    def __init__(self, context, timeout=2):
        self._context = context
        self._timeout = timeout


    def update_share_secret_addresses(self, address, account, share_secret_address):
        if share_secret_address in account.share_secret_addresses:
            raise InvalidTransaction("Duplicacy in share_secret array of user")

        account.share_secret_addresses.append(share_secret_address)
        print ("User account {}".format(account))
        return self._context.set_state(
            {address: account.SerializeToString()}, self._timeout)


    def get_share_secret(self, address):
        ##entries will be a weird list of the form
        ##[address: "318c9fa5d39e9ccd2769115795e384b8e83b3267172ae518136ac49ddc5adf71d87814"
        ##data: "\nB02dbf0f4a3defef38df754122ef7c10fee6a4bb363312367524f86d230e205d459\022$b6de5d5b-7870-49df-971e-0885986bfa96\032
        ##\006seller\"\021978-0-9956537-6-4*\0161-191-790-04532\r1-932866-82-5:\001\000"]

        entries = self._context.get_state(
            addresses=[address],
            timeout=self._timeout)

        try:
            entry = entries[0]
        except Exception as e:
            logging.info("No share mnemonic with address {} can be \
                        found".format(address))
            return False

        share_secret = empty_share_secret()
        share_secret.ParseFromString(entry.data)
        logging.info("This is the account at {} stored on blockchain \
                                {}".format(address, share_secret))
        return share_secret

    def create_share_secret(self, public, payload, share_secret_address, update):

        transaction = empty_share_secret()

        transaction.active = payload.active
        transaction.ownership = payload.ownership
        transaction.secret_hash = payload.secret_hash
        transaction.key = payload.key
        transaction.secret = payload.secret
        transaction.nonce = payload.nonce
        transaction.signed_nonce = payload.signed_nonce
        transaction.nonce_hash = payload.nonce_hash

        ##if the share_secret already exists, then update=True
        ##which implies thast these fields should remain same when this
        #share_secret transaction was first created
        if not update:
            transaction.public = public
            transaction.created_on=payload.created_on
            transaction.idx = payload.idx
            transaction.role = payload.role


        return self._context.set_state(
                    {share_secret_address: transaction.SerializeToString()}, self._timeout)
