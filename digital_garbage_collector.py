import json

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


if __name__ == "__main__":
	from xrpl import account
	from xrpl.clients import JsonRpcClient
	JSON_RPC_URL = "https://s2.ripple.com:51234/"
	# JSON_RPC_URL = "https://s.altnet.rippletest.net:51234"
	client = JsonRpcClient(JSON_RPC_URL)
	wallet_address1 = 'rPnYrAAwgR7YQ8qqL5AexMBCZ2A7826rMN'
	wallet_address2 = 'r49zsuZWw2TLuBm9e5xNePwBnWSJzEXSiP'

	response = account.get_account_info(wallet_address1, client )
	print(json.dumps(response.result, indent=4, sort_keys=True))

	response = account.get_account_info(wallet_address2, client )
	print(json.dumps(response.result, indent=4, sort_keys=True))

	from xrpl.core import addresscodec
	from xrpl import constants
	from struct import pack

	# little endian 16bit array 
	seed_number = pack( '>HHHHHHHH', int('1'), int('2'), int('3'), int('4'), int('5'), int('6'), int('7'), int('8') )
	print(f'{seed_number=}')

	seed_str = addresscodec.encode_seed(seed_number, constants.CryptoAlgorithm('secp256k1'))
	print(f'{seed_str=}')

	from xrpl.wallet import Wallet
	test_wallet = Wallet(seed=seed_str, sequence=response.result['account_data']['Sequence'])
	print(f'{test_wallet.classic_address=}') # "rMCcNuTcajgw7YTgBy1sys3b89QqjUrMpH"
	pass