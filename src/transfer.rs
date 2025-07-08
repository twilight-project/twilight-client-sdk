use address::{Address, AddressType, Network, Script, Standard};
use core::convert::TryInto;
use curve25519_dalek::scalar::Scalar;
use transaction::quisquislib::{
    accounts::Account,
    elgamal::ElGamalCommitment,
    keys::{PublicKey, SecretKey},
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};

use transaction::reference_tx::{Receiver, Sender};
use transaction::{Transaction, TransferTransaction};
use zkvm::zkos_types::{Input, InputData, OutputCoin, Utxo};

use crate::*;
use hex;

use serde::{Deserialize, Serialize};

//Rename dark to stealth in all functions
///Neeeded to stroe the encrypt scalar for future
pub struct TransferTxWallet {
    tx_hex: String,
    encrypt_scalar_hex: String,
}
// ------- qqReciever for Transfer Tx ------- //
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QqReciever {
    amount: i64, //amount to be recieved
    // can be an address hex string or a trading account input json string
    trading_account: String, //Json String of Trading account of reciever
}

impl QqReciever {
    pub fn new(amount: i64, trading_account: String) -> Self {
        Self {
            amount,
            trading_account,
        }
    }
}

// ------- qqSender for Transfer Tx ------- //
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QqSender {
    total_amount: i64,          //total amount to be sent
    input: String,              // input coin to be spent
    receivers: Vec<QqReciever>, //list of recievers
}
impl QqSender {
    pub fn new(total_amount: i64, input: String, receivers: Vec<QqReciever>) -> Self {
        Self {
            total_amount,
            input,
            receivers,
        }
    }
    pub fn to_input(&self) -> Input {
        let input: Input = serde_json::from_str(&self.input).unwrap();
        input
    }
}
///Utility function to convert Jsons into Rust Structs
/// this should be used for processing txs in the browser
fn preprocess_tx_request_frontend(
    tx_vec: String,
    sk: RistrettoSecretKey,
    updated_sender_balance_ser: String,
    updated_balance_reciever_ser: String,
) -> (
    Vec<u64>,
    Vec<u64>,
    Vec<RistrettoSecretKey>,
    Vec<Sender>,
    Vec<Input>,
) {
    // reconstruct tx_vector for WASM
    let tx_vector: Vec<QqSender> = serde_json::from_str(&tx_vec).unwrap();

    //reconstruct sender balance for WASM
    let updated_sender_balance: Vec<u64> =
        serde_json::from_str(&updated_sender_balance_ser).unwrap();

    let updated_reciever_balance: Vec<u64> =
        serde_json::from_str(&updated_balance_reciever_ser).unwrap();

    //derive private key
    /* The twilight wallet only supports a single secret key seed for now */
    /* The same Secretkey can be used for as my input accounts as required */
    // let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);

    //using the same sk for the number of senders
    //let mut sk_vector: Vec<RistrettoSecretKey> = new
    let sk_vector = vec![sk; updated_sender_balance.len()];
    //Create TX_VECTOR for Tx

    let mut sender_array = Vec::<Sender>::new();
    let mut input_vector = Vec::<Input>::new();
    //println!("tx_vector: {:?}", tx_vector);
    // for sender_obj in tx_vector.iter() {
    //     let mut recievers = Vec::<Receiver>::new();
    //     let rec = &sender_obj.receivers;
    //     for j in rec.into_iter() {
    //         let r = Receiver::set_receiver(j.amount, j.to_account());
    //         recievers.push(r);
    //     }
    //     let s = Sender::set_sender(
    //         sender_obj.total_amount,
    //         sender_obj.input_to_qq_account(),
    //         recievers,
    //     );
    //     sender_array.push(s);
    //     input_vector.push(serde_json::from_str(&sender_obj.input).unwrap());
    // }
    (
        updated_sender_balance,
        updated_reciever_balance,
        sk_vector,
        sender_array,
        input_vector,
    )
}
///Utility function to convert Jsons into Rust Structs
/// this for Wasm tests only
// fn preprocess_tx_request(
//     tx_vec: String,
//     secret_vec: String,
//     updated_sender_balance_ser: String,
//     updated_balance_reciever_ser: String,
// ) -> (
//     Vec<u64>,
//     Vec<u64>,
//     Vec<RistrettoSecretKey>,
//     Vec<Sender>,
//     Vec<Input>,
// ) {
//     // reconstruct tx_vector for WASM
//     let tx_vector: Vec<QqSender> = serde_json::from_str(&tx_vec).unwrap();

//     //reconstruct sender balance for WASM
//     let updated_sender_balance: Vec<u64> =
//         serde_json::from_str(&updated_sender_balance_ser).unwrap();

//     let updated_reciever_balance: Vec<u64> =
//         serde_json::from_str(&updated_balance_reciever_ser).unwrap();

//     //reconstruct secret_seed_vec for WASM
//     let secret_seed_vector: Vec<String> = serde_json::from_str(&secret_vec).unwrap();
//     let sender_size = tx_vector.len();
//     let secret_seed_vector_len = secret_seed_vector.len();
//     //check if you have enough secret keys
//     if sender_size != secret_seed_vector_len {
//         panic!("Sender and Secret Key Vector size mismatch");
//     }
//     //recreate seed [u8] from Json Strings
//     let sk_seed_vec: Vec<[u8; 65]> = secret_seed_vector
//         .iter()
//         .map(|i| decode_from_base64(&i))
//         .collect();

//     //create secret key vector
//     let sk_vector: Vec<transaction::quisquislib::ristretto::RistrettoSecretKey> = sk_seed_vec
//         .iter()
//         .map(|i| transaction::quisquislib::keys::SecretKey::from_bytes(i))
//         .collect();

//     //Create TX_VECTOR for Tx

//     let mut sender_array = Vec::<Sender>::new();
//     let mut input_vector = Vec::<Input>::new();
//     //println!("tx_vector: {:?}", tx_vector);
//     for sender_obj in tx_vector.iter() {
//         let mut recievers = Vec::<Receiver>::new();
//         let rec = &sender_obj.receivers;
//         for j in rec.into_iter() {
//             let r = Receiver::set_receiver(j.amount, j.to_account());
//             recievers.push(r);
//         }
//         let s = Sender::set_sender(
//             sender_obj.total_amount,
//             sender_obj.input_to_qq_account(),
//             recievers,
//         );
//         sender_array.push(s);
//         input_vector.push(serde_json::from_str(&sender_obj.input).unwrap());
//     }
//     (
//         updated_sender_balance,
//         updated_reciever_balance,
//         sk_vector,
//         sender_array,
//         input_vector,
//     )
// }

/// Create Quisquis Transaction with anonymity Set
/// Returns Transaction
// Works for single sender and reciever
// seed = Signature string
// sender = Input as json string
// reciever = Either address as Hex String or Input as json string
// amount = Amount to be sent as u64
// address_input = Flag
//  0 ->  reciever is address.
// 1  ->  reciever is input
// anonymity_set = Json String of vector of anonymity Inputs
// returns the tx as Hex string
// pub fn create_quisquis_transaction_single(
//     sk: RistrettoSecretKey,
//     sender_inp: Input,
//     reciever: String, //
//     amount: u64,
//     address_input: bool,
//     updated_sender_balance: u64,
//     anonymity_set: String,
//     fee: u64,
// ) -> String {
//     let updated_sender_balance = vec![updated_sender_balance];
//     let updated_reciever_value = vec![amount];
//     //let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);
//     let sk_vector = vec![sk];

//     let (rec_acc, rec_comm_scalar) = compute_address_input(address_input, reciever.clone());

//     //let sender_inp: Input = serde_json::from_str(&sender).unwrap();
//     let sender_acc = sender_inp.to_quisquis_account().unwrap();

//     let sender_count = 1 as usize;
//     let receiver_count = 1 as usize;
//     // create value vector [sender, reciever, anonymity_set]
//     let value_vector: Vec<i64> = vec![
//         -1 * (amount as i64),
//         amount as i64,
//         0 as i64,
//         0 as i64,
//         0 as i64,
//         0 as i64,
//         0 as i64,
//         0 as i64,
//         0 as i64,
//     ];
//     // ge the anonymity set
//     let anonymity_set_input: Vec<Input> = serde_json::from_str(&anonymity_set).unwrap();
//     // convert anonymity set to account vector
//     let mut anonymity_account_vector: Vec<Account> = anonymity_set_input
//         .iter()
//         .map(|i| i.to_quisquis_account().unwrap())
//         .collect();
//     // create a mutable account vector
//     let mut account_vector = vec![sender_acc, rec_acc];
//     // append the anonymity set to the account vector
//     account_vector.append(&mut anonymity_account_vector);

//     let transfer: Result<TransferTransaction, &'static str>;
//     let scalar_vector: Vec<Scalar> = vec![rec_comm_scalar];
//     let diff: usize = 9 - (sender_count + receiver_count);
//     let mut input_vector = vec![sender_inp];
//     match address_input {
//         false => {
//             let rec_input: Input = Input::input_from_quisquis_account(
//                 &rec_acc,
//                 Utxo::default(),
//                 0,
//                 Network::default(),
//             );
//             input_vector.push(rec_input);
//             input_vector.append(&mut anonymity_set_input.clone());
//             transfer = TransferTransaction::create_quisquis_transaction(
//                 &input_vector,
//                 &value_vector,
//                 &account_vector,
//                 &updated_sender_balance,
//                 &updated_reciever_value,
//                 &sk_vector,
//                 sender_count,
//                 receiver_count,
//                 diff,
//                 Some(&scalar_vector),
//                 fee,
//             );
//         }
//         true => {
//             let rec_inp: Input = serde_json::from_str(&reciever).unwrap();
//             input_vector.push(rec_inp);
//             input_vector.append(&mut anonymity_set_input.clone());
//             transfer = TransferTransaction::create_quisquis_transaction(
//                 &input_vector,
//                 &value_vector,
//                 &account_vector,
//                 &updated_sender_balance,
//                 &updated_reciever_value,
//                 &sk_vector,
//                 sender_count,
//                 receiver_count,
//                 diff,
//                 None,
//                 fee,
//             );
//         }
//     }

//     let transaction: transaction::Transaction = transaction::Transaction::transaction_transfer(
//         transaction::TransactionData::TransactionTransfer(transfer.unwrap()),
//     );

//     let tx_bin = bincode::serialize(&transaction).unwrap();
//     let msg_to_return = hex::encode(&tx_bin);
//     // returns hex encoded tx string
//     msg_to_return
// }

fn compute_address_input(address_input: bool, reciever: String) -> (Account, Scalar) {
    if address_input == false {
        // reciever is address
        // create pk from address
        let pk = Address::from_hex(&reciever, AddressType::default())
            .unwrap()
            .as_coin_address()
            .public_key;
        // create account from pk
        let (account, comm_scalar) = Account::generate_account(pk);
        return (account, comm_scalar);
    } else {
        // reciever is input
        // create account from input
        let input: Input = serde_json::from_str(&reciever).unwrap();
        let account: Account = Input::to_quisquis_account(&input).unwrap();
        return (account, Scalar::zero());
    }
}

// Works for single sender and reciever
// seed = Signature string
// sender = Input as json string
// reciever = Either address as Hex String or Input as json string
// amount = Amount to be sent as u64
// address_input = Flag
//  0 ->  reciever is address
// 1  ->  reciever is input
pub fn create_private_tx_single(
    sk: RistrettoSecretKey,
    sender: String,
    reciever: String,
    amount: u64,
    address_input: bool,
    updated_sender_balance: u64,
    fee: u64,
) -> TransferTxWallet {
    let updated_sender_balance = vec![updated_sender_balance];
    let updated_reciever_balance = vec![amount];
    //let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);
    let sk_vector = vec![sk];

    let (rec_acc, rec_comm_scalar) = compute_address_input(address_input, reciever.clone());

    let sender_inp: Input = serde_json::from_str(&sender).unwrap();
    let sender_acc = sender_inp.to_quisquis_account().unwrap();

    let sender_array = vec![Sender::set_sender(
        -1 * (amount as i64),
        sender_acc.clone(),
        vec![Receiver::set_receiver(amount as i64, rec_acc.clone())],
    )];
    let (value_vector, account_vector, sender_count, receiver_count) =
        Sender::generate_value_and_account_vector(sender_array).unwrap();
    let transfer: Result<(TransferTransaction, Option<Vec<Scalar>>), &'static str>;
    let scalar_vector: Vec<Scalar> = vec![rec_comm_scalar];
    let mut input_vector = vec![sender_inp];
    match address_input {
        false => {
            let rec_input: Input = Input::input_from_quisquis_account(
                &rec_acc,
                Utxo::default(),
                0,
                Network::default(),
            );
            input_vector.push(rec_input);
            transfer = TransferTransaction::create_private_transfer_transaction(
                &value_vector,
                &account_vector,
                &updated_sender_balance,
                &updated_reciever_balance,
                &input_vector,
                &sk_vector,
                sender_count,
                receiver_count,
                Some(&scalar_vector),
                fee,
            );
        }
        true => {
            let rec_inp: Input = serde_json::from_str(&reciever).unwrap();
            input_vector.push(rec_inp);
            transfer = TransferTransaction::create_private_transfer_transaction(
                &value_vector,
                &account_vector,
                &updated_sender_balance,
                &updated_reciever_balance,
                &input_vector,
                &sk_vector,
                sender_count,
                receiver_count,
                None,
                fee,
            );
        }
    }
    //create quisquis dark transfer transaction
    let (transfer_tx, final_comm_scalar) = transfer.unwrap();
    // create dark transaction
    let transaction: Transaction = Transaction::transaction_transfer(
        transaction::TransactionData::TransactionTransfer(transfer_tx),
    );
    let tx_bin = bincode::serialize(&transaction).unwrap();
    let tx_hex = hex::encode(&tx_bin);

    let comm_scalar = match final_comm_scalar {
        Some(x) => x[0],
        None => Scalar::zero(),
    };
    //convert scalar to hex string
    let scalar_hex = hex::encode(comm_scalar.to_bytes());
    let tx_dark_wallet = TransferTxWallet {
        tx_hex,
        encrypt_scalar_hex: scalar_hex,
    };
    //let msg_to_return = serde_json::to_string(&msg_to_return).unwrap();
    //returns hex encoded tx string
    //return Ok(msg_to_return);
    tx_dark_wallet
}
///Create Quisquis Dark Transaction.
///Returns Transaction
pub fn create_private_transfer_transaction(
    tx_vec: String,
    sk: RistrettoSecretKey,
    updated_sender_balance_ser: String,
    updated_balance_reciever_ser: String,
    fee: u64,
) -> String {
    let (updated_sender_balance, updated_reciever_balance, sk_vector, sender_array, inputs_sender) =
        preprocess_tx_request_frontend(
            tx_vec,
            sk,
            updated_sender_balance_ser,
            updated_balance_reciever_ser,
        );

    let (value_vector, account_vector, sender_count, receiver_count) =
        Sender::generate_value_and_account_vector(sender_array).unwrap();

    // create Inputs for recievers with Utxo as 000000000000000000000000000, 0
    let utxo: Utxo = Utxo::default();

    //create vec of Reciver Inputs
    let rec_accounts = &account_vector[sender_count..];
    let mut input_vector = Vec::<Input>::new();
    input_vector.append(&mut inputs_sender.clone());
    for input in rec_accounts.iter() {
        //create address
        let (pk, enc) = input.get_account();
        let out_coin = OutputCoin::new(
            enc.clone(),
            Address::standard_address(Network::default(), pk.clone()).as_hex(),
        );

        let inp = Input::coin(InputData::coin(utxo, out_coin, 0));
        input_vector.push(inp.clone());
    }
    //create quisquis dark transfer transaction
    let transfer = transaction::TransferTransaction::create_private_transfer_transaction(
        &value_vector,
        &account_vector,
        &updated_sender_balance,
        &updated_reciever_balance,
        &input_vector,
        &sk_vector,
        sender_count,
        receiver_count,
        None,
        fee,
    );
    let (tx, _comm_scalar) = transfer.unwrap();
    let transaction: transaction::Transaction = transaction::Transaction::transaction_transfer(
        transaction::TransactionData::TransactionTransfer(tx),
    );

    let tx_bin = bincode::serialize(&transaction).unwrap();
    let msg_to_return = hex::encode(&tx_bin);
    //returns hex encoded tx string
    msg_to_return
}

///Verify Quisquis and Dark Transaction.
pub fn verify_quisquis_tx(tx: String) -> Result<(), &'static str> {
    //decode the tx to binary
    let tx_binary: Vec<u8> = hex::decode(&tx).unwrap();
    // deserialize Tx to type Transaction
    let tx_t: transaction::Transaction = bincode::deserialize(&tx_binary).unwrap();

    //verify transaction
    tx_t.verify()
}
// pub fn get_updated_address_from_transaction(sk: RistrettoSecretKey, tx: String) -> String {
//     //decode the tx to binary
//     let tx_binary: Vec<u8> = hex::decode(&tx).unwrap();
//     // deserialize Tx to type Transaction
//     let tx_t: transaction::Transaction = bincode::deserialize(&tx_binary).unwrap();
//     // create sk from seed
//     //let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);

//     // get all outputs of the transaction
//     let outputs = tx_t.get_tx_outputs();
//     let mut output_addresses: Vec<String> = Vec::new();
//     // search for the output with the same that matches the sk
//     // This will only work if all outputs are coin outputs
//     for output in outputs.iter() {
//         let out_coin = output.output.get_output_coin().unwrap().to_owned();
//         //create ZkosAccount from out_coin
//         let trading_account = TradingAccount::new(out_coin.owner, out_coin.encrypt);
//         let check = trading_account.verify_keypair(&sk);
//         if check == true {
//             let address = trading_account.address;
//             output_addresses.push(address);
//         }
//     }

//     let j = serde_json::to_string(&output_addresses);
//     let msg_to_return = j.unwrap();
//     Ok(msg_to_return)
// }

/// Create burn transaction message

pub fn create_burn_message_transaction(
    input: Input,
    amount: u64,
    ecrypt_scalar_hex: String,
    sk: RistrettoSecretKey,
    init_address: String,
) -> String {
    // create Scalar from hex
    let scalar_bytes = hex::decode(&ecrypt_scalar_hex).unwrap();
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes.try_into().unwrap());

    // create burn transaction
    let burn_tx =
        transaction::Message::create_burn_message(input, amount, scalar, sk, init_address);
    let tx = Transaction::from(burn_tx);
    let tx_bin = bincode::serialize(&tx).unwrap();
    let msg_to_return = hex::encode(&tx_bin);
    //returns hex encoded tx string
    msg_to_return
}

/// Decode zkos tx

pub fn decode_tx(tx: String) -> Transaction {
    //decode the tx to binary
    let tx_binary: Vec<u8> = hex::decode(&tx).unwrap();
    // deserialize Tx to type Transaction
    let tx_t: transaction::Transaction = bincode::deserialize(&tx_binary).unwrap();
    //let tx_json = serde_json::to_string(&tx_t).unwrap();
    //println!("tx_json: {:?}", tx_json);
    //return Ok(tx_json);
    tx_t
}
