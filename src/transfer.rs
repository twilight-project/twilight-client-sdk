use address::{Address, AddressType, Network};
use core::convert::TryInto;
use curve25519_dalek::scalar::Scalar;
use transaction::quisquislib::{accounts::Account, ristretto::RistrettoSecretKey};

use transaction::reference_tx::{Receiver, Sender};
use transaction::{Transaction, TransferTransaction};
use zkvm::zkos_types::{Input, InputData, OutputCoin, Utxo};

use crate::*;
use hex;

use serde::{Deserialize, Serialize};

//Rename dark to stealth in all functions
/// Needed to store the encrypt scalar for future
#[allow(dead_code)]
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
    // pub fn to_output_coin(&self) -> OutputCoin {
    //     let account: crate::TradingAccount = serde_json::from_str(&self.trading_account).unwrap();
    //     let output_coin = crate::OutputCoin::new(account.encrypt, account.address);
    //     output_coin
    // }
    // pub fn to_output(&self) -> Output {
    //     let out_coin = self.to_output_coin();
    //     out_coin.to_output()
    // }

    // pub fn to_input_data(&self, utxo: Utxo, witness: u8) -> InputData {
    //     let out_coin = self.to_output_coin();
    //     out_coin.to_input_data(utxo, witness)
    // }
    // pub fn to_input(&self, utxo: Utxo, witness: u8) -> Input {
    //     let out_coin = self.to_output_coin();
    //     out_coin.to_input(utxo, witness)
    // }
    // // convert the Trading account into a traditional QQ Account
    // pub fn to_account(&self) -> Account {
    //     let account: crate::TradingAccount = serde_json::from_str(&self.trading_account).unwrap();
    //     account.into()
    // }
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

    // pub fn to_reciever_output_coins(&self) -> Vec<OutputCoin> {
    //     let mut output_coins: Vec<OutputCoin> = Vec::new();
    //     for receiver in &self.receivers {
    //         let output_coin = receiver.to_output_coin();
    //         output_coins.push(output_coin);
    //     }
    //     output_coins
    // }

    // pub fn input_to_qq_account(&self) -> Account {
    //     let input: Input = self.to_input();
    //     let out_coin: OutputCoin = input.as_out_coin().unwrap().to_owned();
    //     out_coin.to_quisquis_account()
    // }
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
    // reconstruct tx_vector for WASM (currently unused)
    let _tx_vector: Vec<QqSender> = serde_json::from_str(&tx_vec).unwrap();

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

    let sender_array = Vec::<Sender>::new();
    let input_vector = Vec::<Input>::new();
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
pub fn create_quisquis_transaction_single(
    sk: RistrettoSecretKey,
    sender_inp: Input,
    reciever: String, //
    amount: u64,
    address_input: bool,
    updated_sender_balance: u64,
    anonymity_set: String,
    fee: u64,
) -> String {
    let updated_sender_balance = vec![updated_sender_balance];
    let updated_reciever_value = vec![amount];
    //let sk: RistrettoSecretKey = hex_str_to_secret_key(seed);
    let sk_vector = vec![sk];

    let (rec_acc, rec_comm_scalar) = compute_address_input(address_input, reciever.clone());

    //let sender_inp: Input = serde_json::from_str(&sender).unwrap();
    let sender_acc = sender_inp.to_quisquis_account().unwrap();

    let sender_count = 1 as usize;
    let receiver_count = 1 as usize;
    // create value vector [sender, reciever, anonymity_set]
    let value_vector: Vec<i64> = vec![
        -1 * (amount as i64),
        amount as i64,
        0 as i64,
        0 as i64,
        0 as i64,
        0 as i64,
        0 as i64,
        0 as i64,
        0 as i64,
    ];
    // ge the anonymity set
    let anonymity_set_input: Vec<Input> = serde_json::from_str(&anonymity_set).unwrap();
    // convert anonymity set to account vector
    let mut anonymity_account_vector: Vec<Account> = anonymity_set_input
        .iter()
        .map(|i| i.to_quisquis_account().unwrap())
        .collect();
    // create a mutable account vector
    let mut account_vector = vec![sender_acc, rec_acc];
    // append the anonymity set to the account vector
    account_vector.append(&mut anonymity_account_vector);

    let transfer: Result<TransferTransaction, &'static str>;
    let scalar_vector: Vec<Scalar> = vec![rec_comm_scalar];
    let diff: usize = 9 - (sender_count + receiver_count);
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
            input_vector.append(&mut anonymity_set_input.clone());
            transfer = TransferTransaction::create_quisquis_transaction(
                &input_vector,
                &value_vector,
                &account_vector,
                &updated_sender_balance,
                &updated_reciever_value,
                &sk_vector,
                sender_count,
                receiver_count,
                diff,
                Some(&scalar_vector),
                fee,
            );
        }
        true => {
            let rec_inp: Input = serde_json::from_str(&reciever).unwrap();
            input_vector.push(rec_inp);
            input_vector.append(&mut anonymity_set_input.clone());
            transfer = TransferTransaction::create_quisquis_transaction(
                &input_vector,
                &value_vector,
                &account_vector,
                &updated_sender_balance,
                &updated_reciever_value,
                &sk_vector,
                sender_count,
                receiver_count,
                diff,
                None,
                fee,
            );
        }
    }

    let transaction: transaction::Transaction = transaction::Transaction::transaction_transfer(
        transaction::TransactionData::TransactionTransfer(transfer.unwrap()),
    );

    let tx_bin = bincode::serialize(&transaction).unwrap();
    let msg_to_return = hex::encode(&tx_bin);
    // returns hex encoded tx string
    msg_to_return
}

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
pub fn create_private_transfer_tx_single(
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

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::tx::QqReciever;
//     use crate::tx::QqSender;

//     #[test]
//     fn test_create_quisquis_transfer_tx_single_existing_receiver() {
//         // lets say bob wants to sent 500 tokens to alice from his one account

//         //USING Keplr SEED Directly
//         let sign_str = "PsvekVHEwt6eBn4Ainsq5sSsPr733om7noQRE0MLizUw3LIAv+yPcZoJjqH0DKzyo8q+NhjvHm4VEycExkF7TQ==";

//         // lets create sender accounts to send these amounts from
//         let bob_pk_1 = generate_public_key_from_signature(sign_str).unwrap();

//         let bob_account_1 = account::generate_value_account(bob_pk_1.clone(), 1000u32).unwrap();
//         let bob_acc: Account = serde_json::from_str(&bob_account_1).unwrap();
//         let (bob_pk, bob_enc) = bob_acc.get_account();

//         //convert it to input
//         let utxo: Utxo = Utxo::random();
//         let out_coin: OutputCoin = OutputCoin::new(
//             bob_enc.clone(),
//             Address::standard_address(Network::default(), bob_pk.clone()).as_hex(),
//         );
//         let bob_input = out_coin.to_input(utxo.clone(), 0);

//         let bob_input_str = serde_json::to_string(&bob_input).unwrap();

//         // lets create receiver Input
//         let alice_address = generate_random_address(bob_pk_1.clone()).unwrap();

//         // create TradingAccount JSON from address
//         let alice_account_str =
//             trading_account::generate_zero_trading_account_from_address(alice_address.clone())
//                 .unwrap();
//         let alice_account: TradingAccount = serde_json::from_str(&alice_account_str).unwrap();
//         let alice_qq_account: Account = alice_account.into();
//         let alice_input: Input = Input::input_from_quisquis_account(
//             &alice_qq_account,
//             utxo.clone(),
//             0,
//             Network::default(),
//         );
//         let alice_input_str = serde_json::to_string(&alice_input).unwrap();
//         // get anonymity accounts. Creating them on the fly for testing purposes. Should be retrieved from utxo
//         let (anonymity_account_vector, _anonymity_scalar_vector) =
//             transaction::reference_tx::Sender::create_anonymity_set(1, 1);
//         // convert anonymity accounts to input
//         let anonymity_set_input = anonymity_account_vector
//             .iter()
//             .map(|i| Input::input_from_quisquis_account(i, utxo.clone(), 0, Network::default()))
//             .collect::<Vec<Input>>();
//         let anonymity_input_set_str = serde_json::to_string(&anonymity_set_input).unwrap();

//         // create the tx
//         let tx: Result<String, JsValue> = super::create_quisquis_transaction_single(
//             sign_str,
//             bob_input_str,
//             alice_input_str,
//             500u64,
//             true,
//             500u64,
//             anonymity_input_set_str,
//         );

//         let verify_string = tx.clone().unwrap();
//         //println!("tx: {:?}", verify_string);
//         println!("verify :: {:?}", super::verify_quisquis_tx(verify_string));
//     }
//     #[test]
//     fn test_create_quisquis_transfer_tx_single_receiver_address() {
//         // lets say bob wants to sent 500 tokens to alice from his one account

//         //USING Keplr SEED Directly
//         let sign_str = "PsvekVHEwt6eBn4Ainsq5sSsPr733om7noQRE0MLizUw3LIAv+yPcZoJjqH0DKzyo8q+NhjvHm4VEycExkF7TQ==";

//         // lets create sender accounts to send these amounts from
//         let bob_pk_1 = generate_public_key_from_signature(sign_str).unwrap();

//         let bob_account_1 = account::generate_value_account(bob_pk_1.clone(), 1000u32).unwrap();
//         let bob_acc: Account = serde_json::from_str(&bob_account_1).unwrap();
//         let (bob_pk, bob_enc) = bob_acc.get_account();

//         //convert it to input
//         let utxo: Utxo = Utxo::random();
//         let out_coin: OutputCoin = OutputCoin::new(
//             bob_enc.clone(),
//             Address::standard_address(Network::default(), bob_pk.clone()).as_hex(),
//         );
//         let bob_input = out_coin.to_input(utxo.clone(), 0);

//         let bob_input_str = serde_json::to_string(&bob_input).unwrap();

//         // lets create receiver Input
//         let alice_address = generate_random_address(bob_pk_1.clone()).unwrap();

//         // get anonymity accounts. Creating them on the fly for testing purposes. Should be retrieved from utxo
//         let (anonymity_account_vector, _anonymity_scalar_vector) =
//             transaction::reference_tx::Sender::create_anonymity_set(1, 1);
//         // convert anonymity accounts to input
//         let anonymity_set_input = anonymity_account_vector
//             .iter()
//             .map(|i| Input::input_from_quisquis_account(i, utxo.clone(), 0, Network::default()))
//             .collect::<Vec<Input>>();
//         let anonymity_input_set_str = serde_json::to_string(&anonymity_set_input).unwrap();

//         // create the tx
//         let tx: Result<String, JsValue> = super::create_quisquis_transaction_single(
//             sign_str,
//             bob_input_str,
//             alice_address,
//             500u64,
//             false,
//             500u64,
//             anonymity_input_set_str,
//         );

//         let verify_string = tx.clone().unwrap();
//         println!("tx: {:?}", verify_string);

//         println!("tx length: {:?}", verify_string.len());
//         println!("verify :: {:?}", super::verify_quisquis_tx(verify_string));
//     }
//     #[test]
//     fn test_create_dark_quisquis_tx_single_sender_reciever() {
//         // lets say bob wants to sent 5 tokens to alice from his one account

//         //USING Keplr SEED Directly
//         let sign_str = "PsvekVHEwt6eBn4Ainsq5sSsPr733om7noQRE0MLizUw3LIAv+yPcZoJjqH0DKzyo8q+NhjvHm4VEycExkF7TQ==";

//         // lets create sender accounts to send these amounts from
//         let bob_pk_1 = generate_public_key_from_signature(sign_str).unwrap();

//         let bob_account_1 = account::generate_value_account(bob_pk_1.clone(), 80u32).unwrap();
//         let bob_acc: Account = serde_json::from_str(&bob_account_1).unwrap();
//         let (bob_pk, bob_enc) = bob_acc.get_account();

//         //convert it to input
//         let utxo: Utxo = Utxo::default();
//         let out_coin: OutputCoin = OutputCoin::new(
//             bob_enc.clone(),
//             Address::standard_address(Network::default(), bob_pk.clone()).as_hex(),
//         );
//         let bob_input = out_coin.to_input(utxo.clone(), 0);

//         let bob_input_str = serde_json::to_string(&bob_input).unwrap();

//         // lets create receiver Accounts
//         let receiver_address = generate_random_address(bob_pk_1.clone()).unwrap();

//         // create TradingAccount JSON from address
//         let reciever_account =
//             trading_account::generate_zero_trading_account_from_address(receiver_address.clone())
//                 .unwrap();

//         // so we have 1 senders and 1 receivers,
//         //Create tx_vector
//         let tx_vector: Vec<QqSender> = vec![QqSender {
//             total_amount: -5i64,
//             input: bob_input_str.clone(),
//             receivers: vec![QqReciever {
//                 amount: 5i64,
//                 trading_account: reciever_account.clone(),
//             }],
//         }];

//         let tx_vector_str = serde_json::to_string(&tx_vector).unwrap();

//         //Create sender updated account vector for the verification of sk and bl-v
//         let bl_first_sender: i64 = 80 - 5; //bl-v
//         let updated_balance_sender: Vec<i64> = vec![bl_first_sender];
//         let upd_bl_sender_str = serde_json::to_string(&updated_balance_sender).unwrap();

//         let updated_recevier_balance: Vec<u64> = vec![5];
//         let updated_recevier_balance_ser =
//             serde_json::to_string(&updated_recevier_balance).unwrap();

//         //Create vector of sender secret keys
//         //let sk_sender: Vec<String> = vec![bob_account_sig_1_str.clone()];
//         //let sk_sender_str = serde_json::to_string(&sk_sender).unwrap();

//         //send secret key seed bytes directly
//         let tx: Result<String, JsValue> = super::create_dark_transfer_transaction(
//             tx_vector_str,
//             sign_str,
//             upd_bl_sender_str,
//             updated_recevier_balance_ser,
//         );
//         println!("tx length: {:?}", tx.clone().unwrap().len());
//         let verify_string = tx.clone().unwrap();
//         println!("verify :: {:?}", super::verify_quisquis_tx(verify_string));
//     }

//     #[test]
//     fn test_create_dark_quisquis_tx() {
//         // lets say bob wants to sent 5 tokens to alice and 3 tokens to fay from his one account

//         //USING Keplr SEED Directly
//         let sign_str = "PsvekVHEwt6eBn4Ainsq5sSsPr733om7noQRE0MLizUw3LIAv+yPcZoJjqH0DKzyo8q+NhjvHm4VEycExkF7TQ==";

//         // lets create sender accounts to send these amounts from
//         let bob_pk_1 = generate_public_key_from_signature(sign_str).unwrap();

//         let bob_account_1 = account::generate_value_account(bob_pk_1.clone(), 80u32).unwrap();
//         let bob_acc: Account = serde_json::from_str(&bob_account_1).unwrap();
//         let (bob_pk, bob_enc) = bob_acc.get_account();

//         //convert it to input
//         let utxo: Utxo = Utxo::default();
//         let out_coin: OutputCoin = OutputCoin::new(
//             bob_enc.clone(),
//             Address::standard_address(Network::default(), bob_pk.clone()).as_hex(),
//         );
//         let bob_input = out_coin.to_input(utxo.clone(), 0);

//         let bob_input_str = serde_json::to_string(&bob_input).unwrap();

//         // create another account for bob
//         let bob_pk_2 = generate_public_key_from_signature(sign_str).unwrap();

//         let bob_account_2 = account::generate_value_account(bob_pk_2.clone(), 100u32).unwrap();
//         let bob_acc_2: Account = serde_json::from_str(&bob_account_2).unwrap();
//         let (bob_pk_2, bob_enc_2) = bob_acc_2.get_account();

//         //convert it to input

//         let out_coin_2: OutputCoin = OutputCoin::new(
//             bob_enc_2.clone(),
//             Address::standard_address(Network::default(), bob_pk_2.clone()).as_hex(),
//         );
//         let bob_input_2 = out_coin_2.to_input(utxo.clone(), 0);

//         let bob_input_str_2 = serde_json::to_string(&bob_input_2).unwrap();

//         // lets create receiver Accounts
//         let receiver_address_1 = generate_random_address(bob_pk_1.clone()).unwrap();
//         let receiver_address_2 = generate_random_address(bob_pk_1.clone()).unwrap();

//         // create TradingAccount JSON from address
//         let reciever_account_1 =
//             trading_account::generate_zero_trading_account_from_address(receiver_address_1.clone())
//                 .unwrap();
//         let reciever_account_2 =
//             trading_account::generate_zero_trading_account_from_address(receiver_address_2.clone())
//                 .unwrap();

//         // so we have 2 senders and 2 receivers,
//         //Create tx_vector
//         let tx_vector: Vec<QqSender> = vec![
//             QqSender {
//                 total_amount: -20i64,
//                 input: bob_input_str.clone(),
//                 receivers: vec![QqReciever {
//                     amount: 20i64,
//                     trading_account: reciever_account_1.clone(),
//                 }],
//             },
//             QqSender {
//                 total_amount: -50i64,
//                 input: bob_input_str_2.clone(),
//                 receivers: vec![QqReciever {
//                     amount: 50i64,
//                     trading_account: reciever_account_2.clone(),
//                 }],
//             },
//         ];

//         let tx_vector_str = serde_json::to_string(&tx_vector).unwrap();

//         //Create sender updated account vector for the verification of sk and bl-v
//         let bl_first_sender: i64 = 80 - 20; //bl-v
//         let bl_second_sender: i64 = 100 - 50; //bl-v

//         let updated_balance_sender: Vec<i64> = vec![bl_first_sender, bl_second_sender];
//         let upd_bl_sender_str = serde_json::to_string(&updated_balance_sender).unwrap();

//         let updated_recevier_balance: Vec<u64> = vec![20, 50];
//         let updated_recevier_balance_ser =
//             serde_json::to_string(&updated_recevier_balance).unwrap();

//         //send secret key seed bytes directly
//         let tx: Result<String, JsValue> = super::create_dark_transfer_transaction(
//             tx_vector_str,
//             sign_str,
//             upd_bl_sender_str,
//             updated_recevier_balance_ser,
//         );
//         let verify_string = tx.clone().unwrap();
//         println!("verify :: {:?}", super::verify_quisquis_tx(verify_string));
//     }

//     #[test]
//     fn test_check_tx_api() {
//         let tx_abd = "00000000000000000100000000000000000000000000000002020002000000000000000000000000000000074c5bfe3c1fb5e098735c6eab14636f8d16d85fda716bdc51854719eb5fea1c003a27d4a612190d59881c4b2e8b0f0701f64729510636b6c3e49f971a84746600eeeea95da22187367d5f4218452f8a2e60a7407a58670ecea31630e14b5c833c8a00000000000000306362306636663561613466666165616432373039363639656536313262396533376561346163663335633662646566336337343734626166663632353563633032343238626562363062656539353831336362623530336262613564373439353161663332653261363035396336313336333161366430653732663562343033643837656531346166000000000000000000000000000000000000000000000000000000000000000000000000000000000000546d0e6ab01451797f510d9e45d475ec64cfe2ba30afc0ad45a393fb40a16000de5474e267a5fff225e00de1bf8455cf22817002edb58c2f341dd479a83bfd108a0000000000000030636230663666356161346666616561643237303936363965653631326239653337656134616366333563366264656633633734373462616666363235356363303234323862656236306265653935383133636262353033626261356437343935316166333265326136303539633631333633316136643065373266356234303364383765653134616600020000000000000000000000000000004a0898730539b991fc0b6fb51a57aa0349a6f0cb9f00438d085fb4c7a36354009a34b5c65687b7111e5afcad3fb6ac36a696ca1a3a94df2befbc5f54069285178a00000000000000306362306636663561613466666165616432373039363639656536313262396533376561346163663335633662646566336337343734626166663632353563633032343238626562363062656539353831336362623530336262613564373439353161663332653261363035396336313336333161366430653732663562343033643837656531346166000000000000000060b6ed6441f9debce4888af0ee4ca664811cd091240a82633a168ee37200cc3b2e4c46f33c4e508271356004b66da54a44ce788e93a8801248c3434cb80632328a000000000000003063623066366635616134666661656164323730393636396565363132623965333765613461636633356336626465663363373437346261666636323535636330323432386265623630626565393538313363626235303362626135643734393531616633326532613630353963363133363331613664306537326635623430336438376565313461660200000000000000b0f6f5aa4ffaead2709669ee612b9e37ea4acf35c6bdef3c7474baff6255cc02428beb60bee95813cbb503bba5d74951af32e2a6059c613631a6d0e72f5b403df4989469c986379d6447027bc087eff0da42c8e920295a9763ff777f90bba7154020455d06cb24d082283ec3f8cd9f3cef52787ec2028e70cf631f9b27ac4d4cb0f6f5aa4ffaead2709669ee612b9e37ea4acf35c6bdef3c7474baff6255cc02428beb60bee95813cbb503bba5d74951af32e2a6059c613631a6d0e72f5b403dd6f70d59aba2e53fbd21ac1e3fec6ea9add1672b3ad2b071ad6be47c98b2b86d8a0caf2834b1cc53ca0783fa74f17b738244ba84b8bf928884bf589095acf9370200000000000000e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d768c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134cc61ec8b80cd54f10cc0887df1bc12e8211a8687ac68b5fed27fd2c6ab6619146caba4d2af3661783be5fde8ea66d8fbcf6d4ec48f630ae95b4279028cc3b43ce2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d768c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134caa1a822251724ab3734bc765d24673da702910df38b3b9d8348fedb572db46f3ad63d4052fab2dee359f60fa8a50a7ce26622c0fa5b56a73dfad0f15086717b010000000200000000000000f984b7347e9a3d198a49e77fa00047d8af35f8ede861ddb6247eb50e3fbcca0bc79d7ae2446dfc9e3b7fef4d26aa95ceabed20cd81ea58baf54d3605428adb060200000000000000174dfe23e680eeefe5011ccd7c3704b48f89e5d2f0bebb31f973b6745b88d50ed9e4d12bd9c6f47b333f6244bba7fb1b7315f7865b1b2690b3037835294d3b0902000000000000002e99e55019ed4ea1a7127ee639c1443449536290fca605665eca16cbb62bd306305802a5fd937e50e9a3c9c112daad8c1616a3650d00d497bb2fde6a1b9f170a4434f424832facb6a07f9e2c9330353d7cafa1ce8504e489485356cd8379f5020100000000000000e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d768c9240b456a9e6dc65c377a1048d745f94a08cdb7f44cbcd7b46f34048871134268c66db5ff4cb26bbf082a37baf77712c04cadc4135f29011bb87594142886df059cdf2fb444abdde72411b40c3da3a9d7dc518fadbf2e418bac35a7952361201000000010000000000000019f3859eb4d0b90701f0d82200c72c489de5602177c2c75aa2cddb850c45a00801000000000000000202b273346e3c5ba1dcea9f10ab301287fbd73ec61b8acab26fa038d5749f0001000000000000001235e96792e4c6ce2682316fd55742bd9b72052c66795f5f4e75328effd9c3081b9f0038782e4fd38f336663855004fb951fed992bd1067a4f8e2566bf5aea0b0100000000000000e002000000000000a06a7478010cad4e5a2089ff16fd46a2eefacc5e713e3a4bca3610b126d02950949f7bcbaee227352e542dddd4d07f1612c434e91d97353846e299fe9f522d0086718f8f0c741a7105795871e680a58b0e7e5663b15d3815f4e1cafb0c82fd437cdb14a50ffdbc2651eb07c6a2e8f23097ad53d6d6cc64fbc9b27c1600ae6140c44560d33c00a2e52c77c30ea8e621e7984a49451870c8cb180563efc1669d068759deb4b1210956a7ce163ddb05fe23051b9bdd10773c7c416a04388dd8d907410dfb4ea09c69f766e8f624df69aa8a429802787523a3b7d718c560724f5e06443ad3e56e3b0255248f58368f9cd70c189263a6d68021c14f51663942086a4ea6b786c496e82b1591741828e58ed5acd66f015256324eca3084e7ab74e54554cc8e243b536d876cf52c24c7fff7cc0098f42eeb9f2b6616f695c16ca8c924596668b40add3b8a93d56117847c7a6c549660cff3ee80fb2f02a4a51f076cad427e4b367a81cf4dce432ccb7a74e3f817ad586df6ee950631fef84b1f9527785cb85b04443c76baa77066b7d37c3b8fb4e0f4f0534635344b6797031ed593e85d6e1ce7c387a9098aae3e2b79fd0826066d09cd0218de6910155675811c67ca5a6c0274147c44de49a20bbed94615b7f435b656fa9eadad7fe31f9db73dd9cd0eb63760ab36315de0cccb97312e8ab06bd9187bd2fb071f7cb5fbffd53b4ade16f6c9cadcf2515c9f6130dd1e1995611be9ed5762bb9a269585e32a95d0a67450288dbf91aea691c96146f0007746cfcc6100674fc3be3423779b4e054669f71ce605a5f25d2bba0a5cd689c221639dc644e249e715354192a54eee576c5d3e1a76d958e5b3fcf4d58a2a25817c9119946f5245c4717707fdd362a833e093764aa4db75872ba4c9cc9ea8be1b1abca97c1a7bfd4959935984678099569e2a66249743625a54c3373a062c4206964602dfba7656f57e1c65bedb93e4362a5d680427f65eaff0e4c917c19293b1a6541c85fb2f44141b09e8ef9488815158fa570301000000000000000000";
//         let tx_bytes = hex::decode(tx_abd).unwrap();
//         let tx: transaction::Transaction = bincode::deserialize(&tx_bytes).unwrap();

//         let sign_str = "PsvekVHEwt6eBn4Ainsq5sSsPr733om7noQRE0MLizUw3LIAv+yPcZoJjqH0DKzyo8q+NhjvHm4VEycExkF7TQ==";
//         // let sign_bytes = base64::decode(sign_str).unwrap();
//         //get transfer tx
//         //let transfer_tx =tx.
//         //get sender from Input
//         let inputs = tx.get_tx_inputs();
//         let sender = inputs[0].clone();

//         let sender_string = serde_json::to_string(&sender).unwrap();
//         println!("sender_string :: {:?}", sender_string);

//         let sender_input_coin = sender.as_out_coin().unwrap().to_owned();
//         let owner_address = sender_input_coin.clone().owner;
//         println!("owner_address :: {:?}", owner_address);

//         let sender_input_out: Output = sender_input_coin.to_output();
//         let sender_in_out_str = serde_json::to_string(&sender_input_out).unwrap();

//         let value = decrypt_output_value(sign_str, sender_in_out_str).unwrap();
//         println!("value :: {:?}", value);
//         let outputs = tx.get_tx_outputs();
//         let sender_out = outputs[0].clone();
//         let sender_out_str = serde_json::to_string(&sender_out).unwrap();
//         let value = decrypt_output_value(sign_str, sender_out_str).unwrap();
//         println!("value :: {:?}", value);

//         // let value = decrypt_output_value(&sign_bytes, sender_in_out_str).unwrap();
//         // println!("value :: {:?}", value);
//         let outputs = tx.get_tx_outputs();
//         let sender_out = outputs[0].clone();
//         let sender_out_str = serde_json::to_string(&sender_out).unwrap();
//         let value = decrypt_output_value(sign_str, sender_out_str).unwrap();
//         println!("value :: {:?}", value);
//         //let verify = transaction::reference_tx::verify_transaction(tx);
//         //println!(
//         //  "verify :: {:?}",
//         // super::verify_quisquis_tx(tx_abd.to_string())
//         //);
//         //println!("verify :: {:?}", verify);
//     }

//     #[test]
//     fn test_create_burn_message_tx() {
//         // Construct a dark single tx to prepare data for Burn message
//         // lets say bob wants to sent 5 tokens to alice from his one account
//         //USING Keplr SEED Directly
//         let sign_str = "PsvekVHEwt6eBn4Ainsq5sSsPr733om7noQRE0MLizUw3LIAv+yPcZoJjqH0DKzyo8q+NhjvHm4VEycExkF7TQ==";

//         // lets create sender accounts to send these amounts from
//         let bob_pk_1 = generate_public_key_from_signature(sign_str).unwrap();

//         let bob_account_1 = account::generate_value_account(bob_pk_1.clone(), 1000u32).unwrap();
//         let bob_acc: Account = serde_json::from_str(&bob_account_1).unwrap();
//         let (bob_pk, bob_enc) = bob_acc.get_account();

//         //convert it to input
//         let utxo: Utxo = Utxo::default();
//         let out_coin: OutputCoin = OutputCoin::new(
//             bob_enc.clone(),
//             Address::standard_address(Network::default(), bob_pk.clone()).as_hex(),
//         );
//         let bob_input = out_coin.to_input(utxo.clone(), 0);

//         let bob_input_str = serde_json::to_string(&bob_input).unwrap();

//         // lets create receiver Accounts
//         let receiver_address = generate_random_address(bob_pk_1.clone()).unwrap();

//         //send secret key seed bytes directly
//         let tx: Result<String, JsValue> = super::create_dark_tx_single(
//             sign_str,
//             bob_input_str,
//             receiver_address.clone(),
//             500u64,
//             false,
//             500u64,
//         );
//         // extract tx from result
//         let tx_str = tx.clone().unwrap();
//         // extract tranferwasm from json
//         let transfer_wasm: TransferTxWasm = serde_json::from_str(&tx_str).unwrap();
//         // extract tx from transfer wasm
//         let tx_hex = transfer_wasm.tx;
//         let encrypt = transfer_wasm.encrypt_scalar_hex;

//         // create burn message
//         //decode tx
//         let tx_bytes = hex::decode(tx_hex).unwrap();
//         let tx: transaction::Transaction = bincode::deserialize(&tx_bytes).unwrap();
//         // get outputs from tx
//         let outputs = tx.get_tx_outputs();
//         // get second output
//         let output = outputs[1].clone();
//         let out_json = serde_json::to_string(&output).unwrap();
//         let utxo_json = serde_json::to_string(&utxo).unwrap();
//         // prepare input
//         let burn_input = crate::relayer_ops::create_input_from_output(out_json, utxo_json, 0);
//         let burn_input_str = burn_input.unwrap();
//         // create burn message
//         let burn_message = super::create_burn_message_transaction(
//             burn_input_str,
//             500,
//             encrypt,
//             sign_str,
//             receiver_address,
//         );

//         println!("burn_message :: {:?}", burn_message);
//         // verify burn message
//         let tx = burn_message.clone().unwrap();
//         // decode tx
//         let tx_bytes = hex::decode(tx).unwrap();
//         let tx: transaction::Transaction = bincode::deserialize(&tx_bytes).unwrap();
//         // verify tx
//         let verify = tx.verify();
//         //let verify = super::verify_quisquis_tx(tx.clone());
//         println!("verify :: {:?}", verify);
//     }
//     #[test]
//     fn test_decode_tx() {
//         // create a dark tx
//         // lets say bob wants to sent 5 tokens to alice from his one account
//         //USING Keplr SEED Directly
//         let sign_str = "PsvekVHEwt6eBn4Ainsq5sSsPr733om7noQRE0MLizUw3LIAv+yPcZoJjqH0DKzyo8q+NhjvHm4VEycExkF7TQ==";

//         // lets create sender accounts to send these amounts from
//         let bob_pk_1 = generate_public_key_from_signature(sign_str).unwrap();

//         let bob_account_1 = account::generate_value_account(bob_pk_1.clone(), 80u32).unwrap();
//         let bob_acc: Account = serde_json::from_str(&bob_account_1).unwrap();
//         let (bob_pk, bob_enc) = bob_acc.get_account();

//         //convert it to input
//         let utxo: Utxo = Utxo::default();
//         let out_coin: OutputCoin = OutputCoin::new(
//             bob_enc.clone(),
//             Address::standard_address(Network::default(), bob_pk.clone()).as_hex(),
//         );
//         let bob_input = out_coin.to_input(utxo.clone(), 0);

//         let bob_input_str = serde_json::to_string(&bob_input).unwrap();

//         // create another account for bob
//         let bob_pk_2 = generate_public_key_from_signature(sign_str).unwrap();

//         let bob_account_2 = account::generate_value_account(bob_pk_2.clone(), 100u32).unwrap();
//         let bob_acc_2: Account = serde_json::from_str(&bob_account_2).unwrap();
//         let (bob_pk_2, bob_enc_2) = bob_acc_2.get_account();

//         //convert it to input

//         let out_coin_2: OutputCoin = OutputCoin::new(
//             bob_enc_2.clone(),
//             Address::standard_address(Network::default(), bob_pk_2.clone()).as_hex(),
//         );
//         let bob_input_2 = out_coin_2.to_input(utxo.clone(), 0);

//         let bob_input_str_2 = serde_json::to_string(&bob_input_2).unwrap();

//         // lets create receiver Accounts
//         let receiver_address_1 = generate_random_address(bob_pk_1.clone()).unwrap();
//         let receiver_address_2 = generate_random_address(bob_pk_1.clone()).unwrap();

//         // create TradingAccount JSON from address
//         let reciever_account_1 =
//             trading_account::generate_zero_trading_account_from_address(receiver_address_1.clone())
//                 .unwrap();
//         let reciever_account_2 =
//             trading_account::generate_zero_trading_account_from_address(receiver_address_2.clone())
//                 .unwrap();

//         // so we have 2 senders and 2 receivers,
//         //Create tx_vector
//         let tx_vector: Vec<QqSender> = vec![
//             QqSender {
//                 total_amount: -20i64,
//                 input: bob_input_str.clone(),
//                 receivers: vec![QqReciever {
//                     amount: 20i64,
//                     trading_account: reciever_account_1.clone(),
//                 }],
//             },
//             QqSender {
//                 total_amount: -50i64,
//                 input: bob_input_str_2.clone(),
//                 receivers: vec![QqReciever {
//                     amount: 50i64,
//                     trading_account: reciever_account_2.clone(),
//                 }],
//             },
//         ];

//         let tx_vector_str = serde_json::to_string(&tx_vector).unwrap();

//         //Create sender updated account vector for the verification of sk and bl-v
//         let bl_first_sender: i64 = 80 - 20; //bl-v
//         let bl_second_sender: i64 = 100 - 50; //bl-v

//         let updated_balance_sender: Vec<i64> = vec![bl_first_sender, bl_second_sender];
//         let upd_bl_sender_str = serde_json::to_string(&updated_balance_sender).unwrap();

//         let updated_recevier_balance: Vec<u64> = vec![20, 50];
//         let updated_recevier_balance_ser =
//             serde_json::to_string(&updated_recevier_balance).unwrap();

//         //send secret key seed bytes directly
//         let tx: Result<String, JsValue> = super::create_dark_transfer_transaction(
//             tx_vector_str,
//             sign_str,
//             upd_bl_sender_str,
//             updated_recevier_balance_ser,
//         );

//         let tx = super::decode_tx(tx.clone().unwrap());
//         println!("tx :: {:?}", tx.unwrap());
//     }
// }
