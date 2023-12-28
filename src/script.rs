use address::{Address, AddressType};

use transaction::quisquislib::{
    keys::PublicKey,
    ristretto::{RistrettoPublicKey, RistrettoSecretKey},
};
use transactionapi::rpcclient::{method::*, txrequest::*};
use zkvm::zkos_types::{IOType, Input, Output, OutputCoin, Utxo};

// pub fn create_refenece_deploy_transaction(sk: RistrettoSecretKey, value_sats: u64) -> Transaction {
//     let mut rng = rand::thread_rng();
//     // commitment scalar for encryption and commitment
//     let scalar_commitment = Scalar::random(&mut rng);
//     // derive public key from secret key
//     let pk = RistrettoPublicKey::from_secret_key(&sk, &mut rng);

//     //create InputCoin and OutputMemo
//     let enc_input =
//         ElGamalCommitment::generate_commitment(&pk, scalar_commitment, Scalar::from(value_sats));
//     let coin_address: Address = Address::standard_address(Network::default(), pk.clone());
//     let out_coin = OutputCoin {
//         encrypt: enc_input,
//         owner: coin_address.as_hex(),
//     };
//     let in_data: InputData = InputData::coin(Utxo::default(), out_coin, 0);
//     let coin_input: Input = Input::coin(in_data);
//     let input_account: Account = Account::set_account(pk.clone(), enc_input.clone());
//     //outputMemo
//     let script_address = crate::verify_relayer::create_script_address(Network::default());
//     let commit_memo = Commitment::blinded_with_factor(value_sats, scalar_commitment);

//     let memo_out = OutputMemo {
//         script_address: script_address.clone(),
//         owner: coin_address.as_hex(),
//         commitment: commit_memo.clone(),
//         data: None,
//         timebounds: 0,
//     };
//     let out_data = OutputData::Memo(memo_out);
//     let memo = Output::memo(out_data);
//     // create ValueWitness for input coin / output memo
//     let value_witness = ValueWitness::create_value_witness(
//         coin_input.clone(),
//         sk,
//         memo.clone(),
//         input_account,
//         pk.clone(),
//         commit_memo.to_point(),
//         value_sats,
//         scalar_commitment,
//     );
//     let s_var: ZkvmString = ZkvmString::Commitment(Box::new(commit_memo.clone()));
//     let s_var_vec: Vec<ZkvmString> = vec![s_var];
//     // create Output state
//     let out_state: OutputState = OutputState {
//         nonce: 1,
//         script_address: script_address.clone(),
//         owner: coin_address.as_hex(),
//         commitment: commit_memo.clone(),
//         state_variables: Some(s_var_vec),
//         timebounds: 0,
//     };
//     // create zero value commitment
//     let zero_commitment = Commitment::blinded_with_factor(0, scalar_commitment);
//     let in_state_var = ZkvmString::Commitment(Box::new(zero_commitment.clone()));
//     let in_state_var_vec: Vec<ZkvmString> = vec![in_state_var];
//     // create Input State
//     let temp_out_state = OutputState {
//         nonce: 0,
//         script_address: script_address.clone(),
//         owner: coin_address.as_hex(),
//         commitment: zero_commitment.clone(),
//         state_variables: Some(in_state_var_vec),
//         timebounds: 0,
//     };
//     let zero_proof = vec![scalar_commitment, scalar_commitment];
//     // convert to input
//     let input_state: Input = Input::state(InputData::state(
//         Utxo::default(),
//         temp_out_state.clone(),
//         None,
//         1,
//     ));

//     let output: Vec<Output> = vec![memo.clone(), Output::state(OutputData::State(out_state))];
//     // create statewitness for input state / output state
//     let state_witness: StateWitness =
//         StateWitness::create_state_witness(&input_state, &memo, sk, pk, true);

//     // create witness vector
//     let witness: Vec<Witness> = vec![
//         Witness::ValueWitness(value_witness),
//         Witness::State(state_witness),
//     ];

//     let temp_out_state_verifier = temp_out_state.verifier_view();
//     let iput_state_verifier = Input::state(InputData::state(
//         Utxo::default(),
//         temp_out_state_verifier.clone(),
//         None,
//         1,
//     ));
//     let input: Vec<Input> = vec![coin_input, iput_state_verifier];

//     // create proof of program
//     let correct_program = verify_relayer::contract_initialize_program_with_stack_short();
//     //cretae unsigned Tx with program proof
//     let result = Prover::build_proof(correct_program, &input, &output, true, None);
//     let (prog_bytes, proof) = result.unwrap();

//     // create callproof
//     let call_proof = verify_relayer::create_call_proof(Network::default());
//     //lets create a script tx
//     let script_tx: ScriptTransaction = ScriptTransaction {
//         version: 0,
//         fee: 0,
//         maturity: 0,
//         input_count: 2,
//         output_count: 2,
//         witness_count: 2,
//         inputs: input.to_vec(),
//         outputs: output.to_vec(),
//         program: prog_bytes.to_vec(),
//         call_proof,
//         proof,
//         witness: witness.to_vec(),
//         tx_data: None,
//     };

//     let tx = Transaction::transaction_script(TransactionData::TransactionScript(script_tx));
//     tx
// }

// #[cfg(test)]
// mod test {

//     #[test]
//     fn test_deploy_contract() {
//         let sk = <RistrettoSecretKey as quisquislib::keys::SecretKey>::random(&mut OsRng);
//         let value_sats = 1000;
//         let tx = create_refenece_deploy_transaction(sk, value_sats);
//         println!("Tx  {:?}\n", tx);
//         let verify: Result<(), &str> = tx.verify();
//         println!("Verify  {:?}\n", verify);
//     }

//     #[test]
//     fn create_chain_deploy_tx() {
//         let seed = "r5Mbx5dlqyKTBYXbV5DAWkUQRh54q6YrwFdDJbItxlwLwmRBAoCC/UeEBtDxAvggemy57z4N/uxIzuQkxkLKdA==";
//         let sk: RistrettoSecretKey = quisquislib::keys::SecretKey::from_bytes(seed.as_bytes());
//         println!("sk {:?}", sk);
//         let json_string = r#"{"out_type":"Coin","output":{"Coin":{"encrypt":{"c":[106,163,174,147,81,79,55,141,28,169,116,21,134,81,98,243,135,43,152,117,5,7,161,94,166,168,39,247,227,70,238,23],"d":[122,73,92,91,165,170,231,41,101,208,255,229,221,175,123,102,124,17,113,48,66,228,216,90,0,222,133,245,166,13,208,66]},"owner":"0cf8c2f329b2d11a0864d1ddb7f552da15a5a1b183a38a7ba24b62b50ea12b8e7dd259343a949615ad56a830fef97418c01232548df6b7334e346a75cb16c30c35ed3b9628"}}}"#;
//         let out: Output = serde_json::from_str(json_string).unwrap();
//         let account: Account = out.as_out_coin().unwrap().to_quisquis_account().unwrap();
//         let (pk, _enc) = account.get_account();
//         let verify_acc = account.verify_account(&sk, Scalar::from(19680u64));
//         println!("verify_acc {:?}", verify_acc);

//         // create Utxo
//         let utxo_str = "69984f1209df54a75f117a52d8d2f63c45556df117892bacef059c36c5f79ec800";
//         let utxo_bytes = hex::decode(&utxo_str.to_string()).unwrap();
//         let utxo: Utxo = bincode::deserialize(&utxo_bytes).unwrap();
//         println!("utxo {:?}", utxo);
//         println!("out {:?}", out);
//         let out_coin = out.as_out_coin().unwrap().to_owned();
//         //create input coin
//         let inp_coin = Input::coin(InputData::coin(utxo, out_coin.clone(), 0));
//         // recreate scalar used for coin encryption
//         let scalar_str =
//             "d6734bd76211def507347265dff1422e3752fdcfdbbdcb7cf562e08aaaa21609".to_string();
//         let scalar_bytes = hex::decode(&scalar_str).unwrap();
//         let scalar_commitment = Scalar::from_bytes_mod_order(scalar_bytes.try_into().unwrap());
//         println!("scalar {:?}", scalar_commitment);

//         // create out memo
//         let script_address = crate::verify_relayer::create_script_address(Network::default());
//         let commit_memo = Commitment::blinded_with_factor(19680u64, scalar_commitment);
//         let coin_address = out_coin.owner.clone();
//         let memo_out = OutputMemo {
//             script_address: script_address.clone(),
//             owner: coin_address.clone(),
//             commitment: commit_memo.clone(),
//             data: None,
//             timebounds: 0,
//         };
//         let memo = Output::memo(OutputData::Memo(memo_out));

//         // create ValueWitness for input coin / output memo
//         let value_witness = ValueWitness::create_value_witness(
//             inp_coin.clone(),
//             sk,
//             memo.clone(),
//             account,
//             pk.clone(),
//             commit_memo.to_point(),
//             19680u64,
//             scalar_commitment,
//         );
//         let s_var: ZkvmString = ZkvmString::Commitment(Box::new(commit_memo.clone()));
//         let s_var_vec: Vec<ZkvmString> = vec![s_var];
//         // create Output state
//         let out_state: OutputState = OutputState {
//             nonce: 1,
//             script_address: script_address.clone(),
//             owner: coin_address.clone(),
//             commitment: commit_memo.clone(),
//             state_variables: Some(s_var_vec),
//             timebounds: 0,
//         };
//         // create zero value commitment
//         let zero_commitment = Commitment::blinded_with_factor(0, scalar_commitment);
//         let in_state_var = ZkvmString::Commitment(Box::new(zero_commitment.clone()));
//         let in_state_var_vec: Vec<ZkvmString> = vec![in_state_var];
//         // create Input State
//         let temp_out_state = OutputState {
//             nonce: 0,
//             script_address: script_address.clone(),
//             owner: coin_address,
//             commitment: zero_commitment.clone(),
//             state_variables: Some(in_state_var_vec),
//             timebounds: 0,
//         };
//         let zero_proof = vec![scalar_commitment, scalar_commitment];
//         // convert to input
//         let input_state: Input = Input::state(InputData::state(
//             Utxo::default(),
//             temp_out_state.clone(),
//             None,
//             1,
//         ));

//         // create statewitness for input state / output state
//         let state_witness: StateWitness =
//             StateWitness::create_state_witness(&input_state, &memo, sk, pk, true);

//         // create witness vector
//         let witness: Vec<Witness> = vec![
//             Witness::ValueWitness(value_witness),
//             Witness::State(state_witness),
//         ];
//         let output: Vec<Output> = vec![memo, Output::state(OutputData::State(out_state))];
//         let temp_out_state_verifier = temp_out_state.verifier_view();
//         let iput_state_verifier = Input::state(InputData::state(
//             Utxo::default(),
//             temp_out_state_verifier.clone(),
//             None,
//             1,
//         ));
//         let input: Vec<Input> = vec![inp_coin, iput_state_verifier];
//         // create proof of program
//         let correct_program = verify_relayer::contract_initialize_program_with_stack_short();
//         //cretae unsigned Tx with program proof
//         let result = Prover::build_proof(correct_program, &input, &output, true, None);
//         let (prog_bytes, proof) = result.unwrap();

//         // create callproof
//         let call_proof = verify_relayer::create_call_proof(Network::default());
//         //lets create a script tx
//         let script_tx: ScriptTransaction = ScriptTransaction {
//             version: 0,
//             fee: 0,
//             maturity: 0,
//             input_count: 2,
//             output_count: 2,
//             witness_count: 2,
//             inputs: input.to_vec(),
//             outputs: output.to_vec(),
//             program: prog_bytes.to_vec(),
//             call_proof,
//             proof,
//             witness: witness.to_vec(),
//             tx_data: None,
//         };

//         let tx = Transaction::transaction_script(TransactionData::TransactionScript(script_tx));
//         //convert tx to hex
//         let tx_bin = bincode::serialize(&tx).unwrap();
//         let tx_hex = hex::encode(&tx_bin);
//         println!("tx_hex {:?}", tx_hex);
//         // let utx_json_string: &str = r#"{"output_index":0,"txid":[244,204,253,20,214,243,15,14,203,150,116,42,136,177,47,144,66,40,172,147,241,89,62,63,135,52,198,173,59,71,127,119]}"#;
//         // let utxxx: Utxo = serde_json::from_str(utx_json_string).unwrap();
//         // println!("utxxx {:?}", utxxx);
//         // let utxx_bytes = bincode::serialize(&utxxx).unwrap();
//         // let utxx_hex = hex::encode(&utxx_bytes);
//         // println!("utxx_hex {:?}", utxx_hex);
//     }
// }
use crate::chain::*;
pub fn get_transaction_coin_input_from_address(address_hex: String) -> Result<Input, String> {
    let coin_utxo_vec_result = get_coin_utxo_by_address_hex(address_hex);
    match coin_utxo_vec_result {
        Ok(utxo_vec_hex) => {
            if utxo_vec_hex.len() > 0 {
                let coin_output_result = get_coin_output_by_utxo_id_hex(utxo_vec_hex[0].clone());
                match coin_output_result {
                    Ok(coin_output) => {
                        let input_result = crate::relayer::create_input_from_output(
                            coin_output,
                            utxo_vec_hex[0].clone(),
                            0,
                        );
                        match input_result {
                            Ok(input) => Ok(input),
                            Err(_) => return Err("create_input_from_output error".to_string()),
                        }
                    }
                    Err(_) => return Err("No output found for given utxo".to_string()),
                }
            } else {
                return Err("No utxo found".to_string());
            }
        }
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}
pub fn get_transaction_memo_input_from_address(
    address_hex: String,
    withdraw_amount: u64,
) -> Result<Input, String> {
    let coin_utxo_vec_result = get_memo_utxo_by_address_hex(address_hex);
    match coin_utxo_vec_result {
        Ok(utxo_vec_hex) => {
            if utxo_vec_hex.len() > 0 {
                let coin_output_result = get_memo_output_by_utxo_id_hex(utxo_vec_hex[0].clone());
                match coin_output_result {
                    Ok(coin_output) => {
                        let input_result = crate::relayer::create_input_from_output(
                            coin_output,
                            utxo_vec_hex[0].clone(),
                            withdraw_amount,
                        );
                        match input_result {
                            Ok(input) => Ok(input),
                            Err(_) => return Err("create_input_from_output error".to_string()),
                        }
                    }
                    Err(_) => return Err("No output found for given utxo".to_string()),
                }
            } else {
                return Err("No utxo found".to_string());
            }
        }
        Err(arg) => Err(format!("Error at Response from RPC :{:?}", arg).into()),
    }
}

#[cfg(test)]
mod test {
    use super::get_transaction_coin_input_from_address;
    use crate::utxo_util::*;

    #[test]
    fn get_transaction_coin_input_from_address_test() {
        dotenv::dotenv().expect("Failed loading dotenv");
        let address="0c0a2555a4de4e44e9f10e8d682b1e63f58216ec3ae0d5947e6c65fd1efa952433e0a226db8e1ab54305ce578e39a305871ada6037e76a2ba74bc86e5c8011d736be751ed4".to_string();
        println!(
            "utxo_vec:{:?}",
            get_transaction_coin_input_from_address(address)
        );
    }
}
