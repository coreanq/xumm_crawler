import sys, json, secrets, binascii, time, httpcore, httpx, asyncio
from struct import pack

import xrpl

from xrpl.models.requests.account_lines import AccountLines;
from xrpl.models import transactions as TransactionsModel
from xrpl.models import Response
from xrpl.models.amounts import IssuedCurrencyAmount

from xrpl import clients, utils
from xrpl import account
from xrpl.clients import JsonRpcClient

from xrpl.core import addresscodec
from xrpl import constants
from xrpl.models.response import ResponseStatus, ResponseType

from xrpl.wallet import Wallet
from xrpl.core.addresscodec.codec import SEED_LENGTH 

main_wallet_address = None
delete_wallets_info_from_file = None
sub_wallets_info_from_file = None

arg_divider = 1
arg_remainder = 0

maximum_fee_drops = 20 # 최대 fee

wallet_base_amount = 50 

def get_account_sequene(address):
    response = account.get_account_root(address, client )
    # print(json.dumps(response, indent=4, sort_keys=True))
    return response['Sequence']


def get_currency_transformed_name(name):
    transformed_currency_name = name 
    # 3자리용 currency 와는 별도 처리 필요 함 3자리는 ascii 그대로 사용 그 이상은 hex string 으로 40자 ( 20 char )
    if( len(name) != 3 ):
        transformed_currency_name = bytes(name, 'utf-8')
        transformed_currency_name = binascii.hexlify(transformed_currency_name)
        transformed_currency_name = '{:<040}'.format(str(transformed_currency_name, 'utf-8').upper())
    else:
        transformed_currency_name = transformed_currency_name.upper()

    return  transformed_currency_name

def get_currency_readable_name(name):
    readable_currency_name = '' 
    # 3자리용 currency 와는 별도 처리 필요 함 3자리는 ascii 그대로 사용 그 이상은 hex string 으로 40자 ( 20 char )
    if( len(name) != 3 ):
        name = name.replace('00', '')
        readable_currency_name = str(bytes.fromhex(name), encoding='utf-8')
    else:
        readable_currency_name = name
    return  readable_currency_name

def get_wallet_from_seed_list(seed_list, sequence_number):
    # little endian 16bit array 
    seed_number = pack( '>HHHHHHHH', *seed_list )
    seed_str = addresscodec.encode_seed(seed_number, constants.CryptoAlgorithm('secp256k1'))

    current_wallet = Wallet(seed=seed_str, sequence= sequence_number )
    return current_wallet

# send xrp to main wallet 
def send_payment(src_wallet, target_addr, xrp_amount_in_drops):
    # Prepare transaction ----------------------------------------------------------
    my_transaction = TransactionsModel.Payment(
        account= src_wallet.classic_address, 
        amount= xrp_amount_in_drops,
        destination= target_addr
        )
    # print('{}'.format(my_transaction.to_dict() ) )

    try:
        # Sign transaction -------------------------------------------------------------
        signed_tx = xrpl.transaction.safe_sign_and_autofill_transaction(
                my_transaction, src_wallet, client)
        max_ledger = signed_tx.last_ledger_sequence
        tx_id = signed_tx.get_hash()

        if( int(signed_tx.fee) > maximum_fee_drops ):
            print("\t fee too high {}".format( signed_tx.fee))
            return False 
        # print("Signed transaction:", signed_tx)
        # print("Transaction cost:", utils.drops_to_xrp(signed_tx.fee), "XRP")
        # print("Transaction expires after ledger:", max_ledger)
        print("\nsend from {} hash: {}".format(src_wallet.classic_address, tx_id) )

        tx_response = xrpl.transaction.send_reliable_submission(signed_tx, client)
    except xrpl.clients.XRPLRequestFailureException as e:
        print("\n{}: {}".format(src_wallet.classic_address, e)) 
        pass
    except xrpl.transaction.XRPLReliableSubmissionException as e:
        exit(f"Submit failed: {e}")
    except httpx.HTTPError as e:
        print('\nhttp timeout occur {}'.format(e))
        return False
    except:
        print('\nexcept occur')
        return False
    return True

# send all trust line balance to target wallet 
def send_trustlines_payment(src_wallet, target_wallet_address, target_currency, target_issuer, amount, arg_memo_data = ''):

    # get issuer 의 transfer fee
    try:
        account_response = xrpl.account.get_account_info( target_issuer, client ) 
    except xrpl.clients.XRPLRequestFailureException as e:
        print("\n{}: {}".format(src_wallet.classic_address, e)) 
        pass
    except xrpl.transaction.XRPLReliableSubmissionException as e:
        exit(f"Submit failed: {e}")
    except httpx.HTTPError as e:
        print('\nhttp timeout occur {}'.format(e))
        return False
    except:
        print('\nexcept occur')
        return False

    # 1 billion is 100%
    account_data = account_response.result['account_data']
    transfer_fee = 1000000000
    if( 'TransferRate' in account_data):
        transfer_fee = account_data['TransferRate']

    my_transaction = None 

    # 1 billion is 100%
    if( transfer_fee !=  1000000000 ):
        # solo 의 경우 transfer 가 잡혀있고 이 경우 partial payment 로 진행하도록 유도함 
        payment_flag = TransactionsModel.PaymentFlag.TF_PARTIAL_PAYMENT

        # Prepare transaction ----------------------------------------------------------
        my_transaction = TransactionsModel.Payment(
            account= src_wallet.classic_address,
            amount= IssuedCurrencyAmount( currency= target_currency, issuer= target_issuer, value= amount),
            destination= target_wallet_address,
            flags = payment_flag,
            send_max= IssuedCurrencyAmount( currency= target_currency, issuer= target_issuer, value= amount),
            memos =  [TransactionsModel.Memo( memo_data= arg_memo_data)]
        )
    else:
        # Prepare transaction ----------------------------------------------------------
        my_transaction = TransactionsModel.Payment(
            account= src_wallet.classic_address,
            amount= IssuedCurrencyAmount( currency= target_currency, issuer= target_issuer, value= amount),
            destination= target_wallet_address,
            memos =  [TransactionsModel.Memo( memo_data= bytes(arg_memo_data, 'utf-8').hex() ) ]
        )
    # print('{}'.format(my_transaction.to_dict() ) )

    try:
        # Sign transaction -------------------------------------------------------------
        signed_tx = xrpl.transaction.safe_sign_and_autofill_transaction(
                my_transaction, src_wallet, client)
        max_ledger = signed_tx.last_ledger_sequence
        tx_id = signed_tx.get_hash()

        if( int(signed_tx.fee) > maximum_fee_drops ):
            print("\t fee too high {}".format( signed_tx.fee))
            return False 
        # print("Signed transaction:", signed_tx)
        # print("Transaction cost:", utils.drops_to_xrp(signed_tx.fee), "XRP")
        # print("Transaction expires after ledger:", max_ledger)
        print("\nsend from {} hash: {}".format(src_wallet.classic_address, tx_id) )

        tx_response = xrpl.transaction.send_reliable_submission(signed_tx, client)
    except xrpl.clients.XRPLRequestFailureException as e:
        print("\n{}: {}".format(src_wallet.classic_address, e)) 
        pass
    except xrpl.transaction.XRPLReliableSubmissionException as e:
        exit(f"Submit failed: {e}")
    except httpx.HTTPError as e:
        print('\nhttp timeout occur {}'.format(e))
        return False
    except:
        print('\nexcept occur')
        return False
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


    try:
        # Sign transaction -------------------------------------------------------------
        signed_tx = xrpl.transaction.safe_sign_and_autofill_transaction(
                my_transaction, current_wallet, client)
        max_ledger = signed_tx.last_ledger_sequence
        tx_id = signed_tx.get_hash()

        if( int(signed_tx.fee) > maximum_fee_drops ):
            print("\t fee too high {}".format( signed_tx.fee))
            return False 
        # print("Signed transaction:", signed_tx)
        # print("Transaction cost:", utils.drops_to_xrp(signed_tx.fee), "XRP")
        # print("Transaction expires after ledger:", max_ledger)
        print("\n{} {} hash: {}".format(original_currency_name, current_wallet.classic_address, tx_id) )

        tx_response = xrpl.transaction.send_reliable_submission(signed_tx, client)
    except xrpl.clients.XRPLRequestFailureException as e:
        print("\n{} {}: {}".format(original_currency_name, current_wallet.classic_address, e)) 
        pass
    except xrpl.transaction.XRPLReliableSubmissionException as e:
        exit(f"!!!!!!!!!!!!!!!!!Submit failed: {e}")
    except httpx.HTTPError as e:
        print('\nhttp timeout occur {}'.format(e))
        return False
    except:
        print('\nexcept occur')
        return False

    return True


# delete account and remain xrp to destination addr
# must clean trust line, escrow...
def delete_account(delete_wallet_info_from_file, client):

    target_wallet_info  = None
    current_wallet = None

    while(True):
        result = []
        # 모든 trustlines 을 지워야 delete 가능 
        target_wallet_info = get_wallet_info(delete_wallet_info_from_file)
        current_wallet = target_wallet_info['wallet']

        #delete all trust lines 
        for trust_line in target_wallet_info['lines']:
            set_trust_line(current_wallet, get_currency_readable_name(trust_line['currency']), trust_line['currency'], trust_line['account'], trust_line['limit'], True)
            # 트러스트 라인 지운는 작업을 했다면 처음부터 delete 작업을 하도록 유도
            result.append(False)

        if( len(result) > 0 ):
            print("continue deleting trustlines")
        else:
            break

    # 다시 loop 로 반복되는 경우를 가정하여 계좌 활성화 여부 확인 
    if( xrpl.account.does_account_exist(current_wallet.classic_address, client) == False ):
        print("\tdeactive account detect {}: {}".format( target_wallet_info['name'], current_wallet.classic_address ))
        print("Stop delete Processing due to deactive account")
        return False

    # ledge sequence 의 경우 accouunt delete 시 같이 ledge index 가 일정이상 올라가야지만 적용되는 곳에 사용함 
    account_ledger_sequence = get_account_sequene(current_wallet.classic_address)
    # xrp_open_ledger_sequence = xrpl.ledger.get_latest_open_ledger_sequence(client)
    xrp_validate_ledger_sequence = xrpl.ledger.get_latest_validated_ledger_sequence(client)

    if( account_ledger_sequence + 256 > xrp_validate_ledger_sequence ):
        #  The AccountDelete transaction failed because the account was recently activated. The current ledger index must be at least 256 higher than the account's sequence numbe
        print("Stop delete processing, more time to delete account,  +256 ledger sequence than lastest account sequence number")
        print("xrp ledger seq {} account, lastest seq {}".format( xrp_validate_ledger_sequence, account_ledger_sequence))
        return False


    # Prepare transaction ----------------------------------------------------------
    my_transaction = TransactionsModel.AccountDelete(
        account= current_wallet.classic_address,
        destination= main_wallet_address
    )
    # print('{}'.format(my_transaction.to_dict() ) )

    # Sign transaction -------------------------------------------------------------
    signed_tx = xrpl.transaction.safe_sign_and_autofill_transaction(
            my_transaction, current_wallet, client)
    max_ledger = signed_tx.last_ledger_sequence
    tx_id = signed_tx.get_hash()

    # print("Signed transaction:", signed_tx)
    # print("Transaction cost:", utils.drops_to_xrp(signed_tx.fee), "XRP")
    # print("Transaction expires after ledger:", max_ledger)
    print("\ndelete account {} hash: {}".format(current_wallet.classic_address, tx_id) )

    try:
        tx_response = xrpl.transaction.send_reliable_submission(signed_tx, client)
    except xrpl.clients.XRPLRequestFailureException as e:
        print("\n{}: {}".format(current_wallet.classic_address, e)) 
        pass
    except xrpl.transaction.XRPLReliableSubmissionException as e:
        exit(f"Submit failed: {e}")
    return True

def get_wallet_info(wallet_info_from_file):
    # check wallet validation 
    address = wallet_info_from_file['address']
    seed_list = []
    # wallet_sequence = get_account_sequene(address)
    wallet_sequence = 0

    wallet_info = {}

    for seed_unit in wallet_info_from_file['seed_number']:
        # 6 digit  first 5 digit uint16 data   last 1 digit for crc from xumm api document
        seed_list.append( int(seed_unit[:-1]) )

    current_wallet = get_wallet_from_seed_list(seed_list, wallet_sequence) 

    if( address != current_wallet.classic_address ):
        print("\n{} wallet error private key error".format(wallet_info_from_file['name']) )
        sys.exit()
    else:
        wallet_info['name'] = wallet_info_from_file['name']
        wallet_info['wallet'] = current_wallet
        wallet_info['lines'] = []


        info_request = AccountLines(
            account= current_wallet.classic_address,
        )

        try: 
            response = asyncio.run(client.request_impl( info_request ) )
        except httpx.HTTPError as e:
            print('\nhttp timeout occur {}'.format(e))
            return None
        except:
            print('\nexcept occur')
            return None
        else:
            if response.is_successful():
                # print(json.dumps(response.result['lines'], indent=4, sort_keys=True))
                wallet_info['lines']  = response.result['lines']

        return wallet_info


def make_wallet(max_wallet_count, offset = 0):
    seed_list = []

    wallet_info_json = { "sub_wallets_info": [] } 
    wallet_index_offset = offset 


    for wallet_index in range(max_wallet_count):

        seed_list.clear()

        for i in range(0, 8):
            seed_list.append( secrets.SystemRandom().randint(0, 65535) )

        # little endian 16bit array 
        seed_number = pack( '>HHHHHHHH', *seed_list )
        seed_str = addresscodec.encode_seed(seed_number, constants.CryptoAlgorithm('secp256k1'))

        current_wallet = Wallet(seed=seed_str, sequence=0)

        if( xrpl.account.does_account_exist(current_wallet.classic_address, client) == True ):
            balance =  xrpl.account.get_balance( current_wallet.classic_address, client )  
            if( balance != 0 ):
                print('!!!!!!!!!!!!addr {}, private: {}, balance: {}, seed_number {}'.format(current_wallet.classic_address, current_wallet.private_key, balance, seed_list ) )
        else:
            # seed number(5digit) to secret key
            # from https://github.com/XRPLF/XRPL-Standards/issues/15   value * ( position * 2 + 1 ) % 9 

            secret_key = [] 
            for index, seed_number in enumerate(seed_list):
                temp  = (seed_number * ( index * 2 + 1 )) % 9
                secret_key.append( '{:05}{}'.format(seed_number, temp) )
            
            wallet_info_json["sub_wallets_info"].append( { "name" : "t{:04}".format( wallet_index + wallet_index_offset ), "address": current_wallet.classic_address, "seed_number": secret_key })

        print('t{:04} {}\n'.format(wallet_index + wallet_index_offset, current_wallet.classic_address) )
    
    with open("account_generated.json", "w") as json_file:
        json_file.write( json.dumps(wallet_info_json, indent=4) ) 



if __name__ == "__main__":

    command = ''
    max_wallet_count = 0
    offset = 0

    if( len(sys.argv) < 2 ):
        print("argument missing")
        sys.exit()
    else:
        command = sys.argv[1]

    if( command == 'normal' ):
        arg_divider = int(sys.argv[2])
        arg_remainder = int(sys.argv[3])
    elif( command == 'generate'):
        max_wallet_count = int(sys.argv[2])
        offset = int(sys.argv[3])
    elif( sys.argv[1] == 'delete' ):
        arg_divider = int(sys.argv[2])
        arg_remainder = int(sys.argv[3])
    elif( sys.argv[1] == 'xrp_balance_mover' ):
        arg_divider = int(sys.argv[2])
        arg_remainder = int(sys.argv[3])

    elif( sys.argv[1] == 'wallet_active' ):
        # main wallet 에서 쏴줘야 하므로 1개 인스턴스만 가능 
        pass
    else:
        print("argument type error")
        sys.exit()

    json_data = None 

    with open('account_info.json') as json_file:
        json_data = json.load(json_file)

    main_wallet_address = json_data.get('main_wallet_address', '')

    sub_wallets_info_from_file = json_data.get('sub_wallets_info', [] )
    delete_wallets_info_from_file = json_data.get('delete_wallets_info', [])

    # get trustlines info
    with open('trust_lines.json') as json_file:
        json_data = json.load(json_file)
    trust_lines_from_file = json_data

    JSON_RPC_URL = "https://s2.ripple.com:51234/"
    # JSON_RPC_URL = "https://s.altnet.rippletest.net:51234"
    client = JsonRpcClient(JSON_RPC_URL)

    loop = True

    if( command == 'generate'):
        make_wallet(max_wallet_count, offset)
        pass
    elif( command == 'delete'):
        #delete all trust lines 
        while(True):
            result = []
            for wallet_info_from_file in delete_wallets_info_from_file:
                wallet_index = int( wallet_info_from_file['name'][1:])

                wallet_info = None
                loop = True

                if( arg_remainder == wallet_index % arg_divider ):
                    if( delete_account(wallet_info_from_file, client) == True ):
                        # delete transaction 을 수행한 경우
                        result.append(True)
            if( len(result) == 0 ):
                loop = False

    elif( command == 'xrp_balance_mover'):
        while(True):
            valid_wallet_count = 1
            print('')
            for wallet_info_from_file in sub_wallets_info_from_file:

                address = wallet_info_from_file['address']
                wallet_index = int( wallet_info_from_file['name'][1:])

                wallet_info = None
                loop = True

                if( arg_remainder == wallet_index % arg_divider ):
                    while(loop):
                        wallet_info = get_wallet_info(wallet_info_from_file)

                        if( wallet_info != None ):
                            # print('{}({:03}):( {} ), '.format( wallet_info['name'], valid_wallet_count, wallet_info['wallet'].classic_address[-4:] ), end= '', flush= True )
                            print('{}({:03}):( {:03} ), '.format( wallet_info['name'], valid_wallet_count, len(wallet_info['lines']) ), end= '', flush= True )
                            valid_wallet_count = valid_wallet_count + 1

                            #####################################################################################
                            # main wallet -> sub wallet 
                            # seed_list = []
                            # main_wallet = get_wallet_from_seed_list(seed_list, 0)
                            # result = []
                            # for trust_line in wallet_info['lines']:
                            #     readable_currency = get_currency_readable_name(trust_line['currency'])
                            #     if( readable_currency == 'XFAMOUS'):
                            #         if( trust_line['balance'] == '0'):
                            #             result.append(True)
                            #             break

                            # if( len(result) != 0 ):
                            #     send_trustlines_payment(main_wallet, wallet_info['wallet'].classic_address, get_currency_transformed_name('XFAMOUS'), 'r9ZfGV6RpBNA6oewp3WLeyhE5fqvFaMoUs', '1', arg_memo_data='1 XRP at $589 is inevitable' )
                            # loop = False

                            # balance check
                            target_wallet = wallet_info['wallet']
                            try:
                                account_response = xrpl.account.get_account_info( target_wallet.classic_address, client ) 
                            except xrpl.clients.XRPLRequestFailureException as e:
                                print("\n{}: {}".format(target_wallet.classic_address, e)) 
                                pass
                            except xrpl.transaction.XRPLReliableSubmissionException as e:
                                exit(f"Submit failed: {e}")
                            except httpx.HTTPError as e:
                                print('\nhttp timeout occur {}'.format(e))
                            except:
                                print('\nexcept occur')
                            else:
                                # trustlines reserve 포함 잔고 확인 
                                balance_in_drops = int(account_response.result['account_data']['Balance'])

                                send_xrp_in_drops = 0
                                baseline_drops = int(xrpl.utils.xrp_to_drops(wallet_base_amount))
                                if( balance_in_drops > baseline_drops ):
                                    send_xrp_in_drops = balance_in_drops - baseline_drops

                                if( send_xrp_in_drops > 0 ):
                                    send_payment(target_wallet, main_wallet_address, str(send_xrp_in_drops) )
                                # 지갑 정보를 읽은 경우 이므로 다른 지갑 정보 얻도록 함 
                                loop = False

    elif( command == 'wallet_active'):
        seed_list = []
        main_wallet = get_wallet_from_seed_list(seed_list, 0)
        result_list = []
        # 완료 될때까지 루프 돔 
        while(loop):
            print("\n\n")
            for wallet_info_from_file in sub_wallets_info_from_file:
                target_wallet_address = wallet_info_from_file['address']
                target_wallet_name = wallet_info_from_file['name']
                # 계좌 활성화 여부 확인 
                if( xrpl.account.does_account_exist(target_wallet_address, client) == False ):
                    send_payment(main_wallet, target_wallet_address, xrpl.utils.xrp_to_drops(wallet_base_amount) )
                    result_list.append(False)
                    print('{} activate '.format( target_wallet_name), end= '')
                else:
                    print('{} '.format( target_wallet_name), end= '')

            if( len(result_list) == 0 ):
                loop = False
                break
        pass
        print('success')

    else:
        while(True):
            # check wallet validation 
            valid_wallet_count = 1
            for wallet_info_from_file in sub_wallets_info_from_file:

                address = wallet_info_from_file['address']
                wallet_index = int( wallet_info_from_file['name'][1:])

                wallet_info = None
                loop = True

                if( arg_remainder == wallet_index % arg_divider ):
                    while(loop):
                        wallet_info = get_wallet_info(wallet_info_from_file)
                        if( wallet_info != None ):
                            # print('{}({:03}):( {} ), '.format( wallet_info['name'], valid_wallet_count, wallet_info['wallet'].classic_address[-4:] ), end= '', flush= True )
                            print('{}({:04}):( {:04} ), '.format( wallet_info['name'], valid_wallet_count, len(wallet_info['lines']) ), end= '', flush= True )
                            valid_wallet_count = valid_wallet_count + 1

                            # fee 요청하는 경우 느려짐 
                            # fee = xrpl.ledger.get_fee(client)

                            for line in wallet_info['lines']:
                                if( float(line['balance']) > 0 ):
                                    if( send_trustlines_payment( wallet_info['wallet'], main_wallet_address, line['currency'], line['account'], line['balance'] ) == True ):
                                    # if( send_trustlines_payment( wallet_info['wallet'], 'rfaMouSE9KVR8P1k8YfVXaJWts1RxGaPd6', line['currency'], line['account'], '1', arg_memo_data='1 XRP at $589 is inevitable' ) == True ):
                                        print('\t{}, {} -> {}'.format( get_currency_readable_name(line['currency'] ) , line['balance'], wallet_info['name'] ))
                            pass

                            # 이미 trustline 에 추가 된 경우만 삭제 
                            for remove_trust_line in trust_lines_from_file['remove']:
                                original_currency_name = remove_trust_line['currency']
                                transformed_currency_name = get_currency_transformed_name(original_currency_name)
                                isTrustLineExist = False

                                for line in wallet_info['lines']:
                                    if( transformed_currency_name == line['currency'] ):
                                        isTrustLineExist = True
                                        break

                                if ( isTrustLineExist == True ):
                                    if( set_trust_line(wallet_info['wallet'], original_currency_name, transformed_currency_name, remove_trust_line['issuer'], remove_trust_line['limit'], True) == True ):
                                        print('\tremove {} in {}'.format( original_currency_name, wallet_info['name'] ))

                            # 이미 trust line 에 추가 되었다면 추가 금지 
                            for add_trust_line in trust_lines_from_file['add']:
                                original_currency_name = add_trust_line['currency']
                                transformed_currency_name = get_currency_transformed_name(original_currency_name)
                                isTrustLineExist = False

                                for line in wallet_info['lines']:
                                    if( transformed_currency_name == line['currency'] ):
                                        isTrustLineExist = True
                                        break

                                if ( isTrustLineExist == False ):
                                    if( set_trust_line(wallet_info['wallet'], original_currency_name, transformed_currency_name, add_trust_line['issuer'], add_trust_line['limit'], False) == True):
                                        print('\tadd {} to {}'.format( original_currency_name, wallet_info['name'] ))

                            # 지갑 정보를 읽은 경우 이므로 다른 지갑 정보 얻도록 함 
                            loop = False
                        pass
            print("")

