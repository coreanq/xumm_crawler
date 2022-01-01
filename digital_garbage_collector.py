import json
import binascii
import xrpl

from xrpl.models import currencies, transactions as TransactionsModel

from xrpl import utils
from xrpl import account
from xrpl.clients import JsonRpcClient

from xrpl.core import addresscodec
from xrpl import constants
from struct import pack

from xrpl.wallet import Wallet
from xrpl.core.addresscodec.codec import SEED_LENGTH 

# # Define the network client
# from xrpl.clients import JsonRpcClient
# from xrpl.core.addresscodec.codec import SEED_LENGTH
# JSON_RPC_URL = "https://s.altnet.rippletest.net:51234/"
# client = JsonRpcClient(JSON_RPC_URL)

# # Create a wallet using the testnet faucet:
# # https://xrpl.org/xrp-testnet-faucet.html
# from xrpl.wallet import generate_faucet_wallet
# test_wallet = generate_faucet_wallet(client, debug=True)

# print(f'{test_wallet.public_key=}')
# print(f'{test_wallet.private_key=}')
# print(f'{test_wallet.seed=}')
# print(f'{test_wallet.sequence=}') 

# # Create an account str from the wallet
# test_account = test_wallet.classic_address

# # Derive an x-address from the classic address:
# # https://xrpaddress.info/
# from xrpl.core import addresscodec
# test_xaddress = addresscodec.classic_address_to_xaddress(test_account, tag=12345, is_test_network=True)
# print("\nClassic address:\n\n", test_account)
# print("X-address:\n\n", test_xaddress)


# # Look up info about your account
# from xrpl.models.requests.account_info import AccountInfo
# acct_info = AccountInfo(
#     account=test_account,
#     ledger_index="validated",
#     strict=True,
# )
# response = client.request(acct_info)
# result = response.result
# print("response.status: ", response.status)
# import json
# print(json.dumps(response.result, indent=4, sort_keys=True))


# # Prepare payment
# from xrpl.models.transactions import Payment
# from xrpl.utils import xrp_to_drops
# my_tx_payment = Payment(
#     account=test_account,
#     amount=xrp_to_drops(22),
#     destination="rPT1Sjq2YGrBMTttX4GZHjKu9dyfzbpAYe",
# )

# # Sign the transaction
# from xrpl.transaction import safe_sign_and_autofill_transaction

# my_tx_payment_signed = safe_sign_and_autofill_transaction(my_tx_payment, test_wallet, client)

# # Submit and send the transaction
# from xrpl.transaction import send_reliable_submission

# tx_response = send_reliable_submission(my_tx_payment_signed, client)


# print(tx_response)


def get_account_sequene(address):
    response = account.get_account_info(address, client )
    print(json.dumps(response.result, indent=4, sort_keys=True))
    return response.result['account_data']['Sequence']


def get_trust_line_info(address):
    responses = account.get_account_transactions(address, client )
    for item in responses:
        if( item['tx']['TransactionType'] == 'TrustSet'):
            print(json.dumps(item['tx'], indent=4, sort_keys=True))




if __name__ == "__main__":
    sub_wallet_list = {}

    json_data = ''
    with open('account_info.json') as json_file:
        json_data = json.load(json_file)

    main_wallet_address = json_data['main_wallet_address']
    sub_wallets_info_from_file = json_data['sub_wallets_info']

    JSON_RPC_URL = "https://s2.ripple.com:51234/"
    # JSON_RPC_URL = "https://s.altnet.rippletest.net:51234"
    client = JsonRpcClient(JSON_RPC_URL)


    # check wallet validation 
    for wallet_info_dict in sub_wallets_info_from_file:

        address = wallet_info_dict['address']

        wallet_sequence = get_account_sequene(address)

        # get_trust_line_info(address)

        seed_list = []
        for seed_unit in wallet_info_dict['seed_number']:
            # 6 digit  first 5 digit uint16 data   last 1 digit for crc from xumm api document
            seed_list.append( int(seed_unit[:-1]) )

        # little endian 16bit array 
        seed_number = pack( '>HHHHHHHH', *seed_list )
        seed_str = addresscodec.encode_seed(seed_number, constants.CryptoAlgorithm('secp256k1'))

        test_wallet = Wallet(seed=seed_str, sequence=wallet_sequence)
        print(f'{test_wallet.classic_address=}') # "rMCcNuTcajgw7YTgBy1sys3b89QqjUrMpH"

        if( address != test_wallet.classic_address ):
            print("error address info ")
        else:
            sub_wallet_list[wallet_info_dict['name']] = test_wallet

    # # Prepare transaction ----------------------------------------------------------
    my_payment = TransactionsModel.Payment(
        account= sub_wallet_list['1'].classic_address,
        amount= utils.xrp_to_drops(0.0001),
        destination= main_wallet_address
    )
    # print('{}'.format(my_payment.to_dict() ) )

    # print( xrpl.ledger.get_fee(client) )

    # # Sign transaction -------------------------------------------------------------
    # signed_tx = xrpl.transaction.safe_sign_and_autofill_transaction(
    #         my_payment, sub_wallet_list['1'], client)
    # max_ledger = signed_tx.last_ledger_sequence
    # tx_id = signed_tx.get_hash()
    # print("Signed transaction:", signed_tx)
    # print("Transaction cost:", utils.drops_to_xrp(signed_tx.fee), "XRP")
    # print("Transaction expires after ledger:", max_ledger)
    # print("Identifying hash:", tx_id)

    # try:
    #     tx_response = xrpl.transaction.send_reliable_submission(signed_tx, client)
    # except xrpl.transaction.XRPLReliableSubmissionException as e:
    #     exit(f"Submit failed: {e}")

    from xrpl.models.amounts import IssuedCurrencyAmount


    target_currency = 'POLAR'
    target_currency = bytes(target_currency, 'utf-8')

    target_currency = binascii.hexlify(target_currency)
    target_currency = '{:<040}'.format(str(target_currency, 'utf-8').upper())

    target_issuer = 'rfdistkMFGQ7HAgu5JvsQdRHbm15EMgWmX'

    # to remove trust line limit set to 0
    target_limit = '0'
    issued = IssuedCurrencyAmount(  currency=target_currency, issuer= target_issuer, value= target_limit)

    my_payment = TransactionsModel.TrustSet (
        account= sub_wallet_list['1'].classic_address,
        limit_amount= issued,
        flags= TransactionsModel.TrustSetFlag.TF_SET_NO_RIPPLE
    )

    # Sign transaction -------------------------------------------------------------
    signed_tx = xrpl.transaction.safe_sign_and_autofill_transaction(
            my_payment, sub_wallet_list['1'], client)
    max_ledger = signed_tx.last_ledger_sequence
    tx_id = signed_tx.get_hash()
    print("Signed transaction:", signed_tx)
    print("Transaction cost:", utils.drops_to_xrp(signed_tx.fee), "XRP")
    print("Transaction expires after ledger:", max_ledger)
    print("Identifying hash:", tx_id)

    try:
        tx_response = xrpl.transaction.send_reliable_submission(signed_tx, client)
    except xrpl.transaction.XRPLReliableSubmissionException as e:
        exit(f"Submit failed: {e}")

    pass