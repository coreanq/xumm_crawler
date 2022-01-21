from math import remainder

import time
import sys, json
import binascii
import xrpl

from xrpl.models.requests.account_lines import AccountLines;
from xrpl.models import currencies, transactions as TransactionsModel
from xrpl.models import Response
from xrpl.models.amounts import IssuedCurrencyAmount

from xrpl import utils
from xrpl import account
from xrpl.clients import JsonRpcClient

from xrpl.core import addresscodec
from xrpl import constants
from struct import pack
from xrpl.models.response import ResponseStatus, ResponseType

from xrpl.wallet import Wallet
from xrpl.core.addresscodec.codec import SEED_LENGTH 

# # Create a wallet using the testnet faucet:
# # https://xrpl.org/xrp-testnet-faucet.html
# from xrpl.wallet import generate_faucet_wallet
# test_wallet = generate_faucet_wallet(client, debug=True)

# print(f'{test_wallet.public_key=}')
# print(f'{test_wallet.private_key=}')
# print(f'{test_wallet.seed=}')
# print(f'{test_wallet.sequence=}') 

main_wallet_address = None
sub_wallets_info_from_file = None
sub_wallet_list = []

arg_divider = 1
arg_remainder = 0

maximum_fee_drops = 20 # 최대 fee

def get_account_sequene(address):
    response = account.get_account_info(address, client )
    # print(json.dumps(response.result, indent=4, sort_keys=True))
    return response.result['account_data']['Sequence']


def get_currency_transformed_name(name):
    transformed_currency_name = name 
    # 3자리용 currency 와는 별도 처리 필요 함 3자리는 ascii 그대로 사용 그 이상은 hex string 으로 40자 ( 20 char )
    if( len(name) != 3 ):
        transformed_currency_name = bytes(name, 'utf-8')
        transformed_currency_name = binascii.hexlify(transformed_currency_name)
        transformed_currency_name = '{:<040}'.format(str(transformed_currency_name, 'utf-8').upper())

    return  transformed_currency_name

def get_currency_readable_name(name):
    readable_currency_name = '' 
    # 3자리용 currency 와는 별도 처리 필요 함 3자리는 ascii 그대로 사용 그 이상은 hex string 으로 40자 ( 20 char )
    if( len(name) != 3 ):
        readable_currency_name = bytes.fromhex(name).decode('ASCII')
    else:
        readable_currency_name = name

    return  readable_currency_name

# send all trust line balance to main wallet 
def send_payment(current_wallet, target_currency, target_issuer, target_limit):
    # Prepare transaction ----------------------------------------------------------
    my_transaction = TransactionsModel.Payment(
        account= current_wallet.classic_address,
        amount= IssuedCurrencyAmount( currency= target_currency, issuer= target_issuer, value= target_limit),
        destination= main_wallet_address
    )
    # print('{}'.format(my_transaction.to_dict() ) )

    # Sign transaction -------------------------------------------------------------
    signed_tx = xrpl.transaction.safe_sign_and_autofill_transaction(
            my_transaction, current_wallet, client)
    max_ledger = signed_tx.last_ledger_sequence
    tx_id = signed_tx.get_hash()

    if( int(signed_tx.fee) > maximum_fee_drops ):
        return False 
    # print("Signed transaction:", signed_tx)
    # print("Transaction cost:", utils.drops_to_xrp(signed_tx.fee), "XRP")
    # print("Transaction expires after ledger:", max_ledger)
    print("send from {} hash: {}".format(current_wallet.classic_address, tx_id) )

    try:
        tx_response = xrpl.transaction.send_reliable_submission(signed_tx, client)
    except xrpl.clients.XRPLRequestFailureException as e:
        print("{}: {}".format(current_wallet.classic_address, e)) 
        pass
    except xrpl.transaction.XRPLReliableSubmissionException as e:
        exit(f"Submit failed: {e}")
    return True

def set_trust_line(current_wallet, original_currency_name, transformed_currency_name, target_issuer, target_limit, is_delete):

    flag = TransactionsModel.TrustSetFlag.TF_SET_NO_RIPPLE
    # to remove trust line limit set to 0
    if( is_delete == True ):
        target_limit = '0'
        flag = TransactionsModel.TrustSetFlag.TF_SET_NO_RIPPLE | TransactionsModel.TrustSetFlag.TF_CLEAR_FREEZE

    my_transaction = TransactionsModel.TrustSet (
        account= current_wallet.classic_address ,
        limit_amount= IssuedCurrencyAmount( currency= transformed_currency_name, issuer= target_issuer, value= target_limit),
        flags= flag
    )

    # Sign transaction -------------------------------------------------------------
    signed_tx = xrpl.transaction.safe_sign_and_autofill_transaction(
            my_transaction, current_wallet, client)
    max_ledger = signed_tx.last_ledger_sequence
    tx_id = signed_tx.get_hash()

    if( int(signed_tx.fee) > maximum_fee_drops ):
        return False
    # print("Signed transaction:", signed_tx)
    # print("Transaction cost:", utils.drops_to_xrp(signed_tx.fee), "XRP")
    # print("Transaction expires after ledger:", max_ledger)
    print("{} {} hash: {}".format(original_currency_name, current_wallet.classic_address, tx_id) )

    try:
        tx_response = xrpl.transaction.send_reliable_submission(signed_tx, client)
    except xrpl.clients.XRPLRequestFailureException as e:
        print("{} {}: {}".format(original_currency_name, current_wallet.classic_address, e)) 
        pass
    except xrpl.transaction.XRPLReliableSubmissionException as e:
        exit(f"!!!!!!!!!!!!!!!!!Submit failed: {e}")

    return True


def get_wallet_info():
    result = []
    # check wallet validation 
    for index, wallet_info_dict in enumerate(sub_wallets_info_from_file):

        wallet_name = wallet_info_dict['name']
        wallet_index = int(wallet_name[1:]) % arg_divider

        if( wallet_index != arg_remainder ):
            continue

        # wallet_sequence = get_account_sequene(address)

        address = wallet_info_dict['address']
        seed_list = []

        for seed_unit in wallet_info_dict['seed_number']:
            # 6 digit  first 5 digit uint16 data   last 1 digit for crc from xumm api document
            seed_list.append( int(seed_unit[:-1]) )

        # little endian 16bit array 
        seed_number = pack( '>HHHHHHHH', *seed_list )
        seed_str = addresscodec.encode_seed(seed_number, constants.CryptoAlgorithm('secp256k1'))

        current_wallet = Wallet(seed=seed_str, sequence= 0 )
        # print('{:02}: {}'.format( index, current_wallet.classic_address)) # "rMCcNuTcajgw7YTgBy1sys3b89QqjUrMpH"
        print('{}({:03}):( {} ), '.format( wallet_info_dict['name'], index, current_wallet.classic_address[-4:] ), end= '', flush=True ) # "rMCcNuTcajgw7YTgBy1sys3b89QqjUrMpH"

        if( address != current_wallet.classic_address ):
            print("\n{} wallet error private key error".format(wallet_info_dict['name']) )
            result.append(False)
            break
        else:
            wallet_info = {}
            wallet_info['name'] = wallet_info_dict['name']
            wallet_info['wallet'] = current_wallet
            wallet_info['lines'] = []


            info_request = AccountLines(
                account= current_wallet.classic_address,
            )

            response = client.request(info_request)

            if( response.status == ResponseStatus.SUCCESS ):
                for line in response.result['lines']:
                    # print(json.dumps(response.result['lines'], indent=4, sort_keys=True))
                    # if( float(line['balance']) > 0 ):
                    wallet_info['lines']  = response.result['lines']

            # add wallet info
            sub_wallet_list.append( wallet_info )

    print('')
    if( len(result) != 0 ):
        return False
    else:
        return True

    pass


if __name__ == "__main__":

    loop = False


    if( len(sys.argv) >= 3):
        arg_divider = int(sys.argv[1])
        arg_remainder = int(sys.argv[2])
        if( len(sys.argv) == 4):
            loop = True
    else:
        print("argument missing")
        sys.exit()

    json_data = ''
    with open('account_info.json') as json_file:
        json_data = json.load(json_file)

    main_wallet_address = json_data['main_wallet_address']
    sub_wallets_info_from_file = json_data['sub_wallets_info']

    with open('trust_lines.json') as json_file:
        json_data = json.load(json_file)
    
    trust_lines_from_file = json_data

    JSON_RPC_URL = "https://s2.ripple.com:51234/"
    # JSON_RPC_URL = "https://s.altnet.rippletest.net:51234"
    client = JsonRpcClient(JSON_RPC_URL)


    while(True):
        sub_wallet_list.clear()
        if( get_wallet_info() == True ):
            for wallet_dict in sub_wallet_list:

                # fee 요청하는 경우 느려짐 
                # fee = xrpl.ledger.get_fee(client)
                # 잔고 확인 된 것은 main wallet 으로 전송 
                # if( float(fee) > 10 ):
                #     print("fee to high {}".format( fee ))
                #     time.sleep(1)
                #     continue

                for line in wallet_dict['lines']:
                    if( float(line['balance']) > 0 ):
                        if( send_payment( wallet_dict['wallet'], line['currency'], line['account'], line['balance'] ) == True ):
                            print('\t{}, {} -> {}'.format( get_currency_readable_name(line['currency'] ) , line['balance'], wallet_dict['name'] ))
                pass

                # 이미 trust line 에 추가 되었다면 추가 금지 
                for add_trust_line in trust_lines_from_file['add']:
                    original_currency_name = add_trust_line['currency']
                    transformed_currency_name = get_currency_transformed_name(original_currency_name)
                    isTrustLineExist = False

                    for line in wallet_dict['lines']:
                        if( transformed_currency_name == line['currency'] ):
                            isTrustLineExist = True
                            break

                    if ( isTrustLineExist == False ):
                        if( set_trust_line(wallet_dict['wallet'], original_currency_name, transformed_currency_name, add_trust_line['issuer'], add_trust_line['limit'], False) == True):
                            print('\tadd {} to {}'.format( original_currency_name, wallet_dict['name'] ))

                # 이미 trustline 에 추가 된 경우만 삭제 
                for remove_trust_line in trust_lines_from_file['remove']:
                    original_currency_name = remove_trust_line['currency']
                    transformed_currency_name = get_currency_transformed_name(original_currency_name)
                    isTrustLineExist = False

                    for line in wallet_dict['lines']:
                        if( transformed_currency_name == line['currency'] ):
                            isTrustLineExist = True
                            break

                    if ( isTrustLineExist == True ):
                        if( set_trust_line(wallet_dict['wallet'], original_currency_name, transformed_currency_name, remove_trust_line['issuer'], remove_trust_line['limit'], True) == True ):
                            print('\tremove {} in {}'.format( original_currency_name, wallet_dict['name'] ))

        else:
            loop = False

        if( loop == False ):
            break
