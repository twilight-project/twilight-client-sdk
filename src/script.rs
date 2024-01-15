use address::Network;

use crate::{chain::*, programcontroller::ContractManager};
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use transaction::{quisquislib::ristretto::RistrettoSecretKey, Transaction, TransactionData};
use zkvm::{
    zkos_types::{Input, Output, OutputMemo, OutputState, Utxo},
    Commitment, InputData, OutputData, String as ZkvmString,
};
/// Broadcasts a contract deploy transaction to the ZKOS Server on chain.
/// @param sk: RistrettoSecretKey of the coin owner
/// @param value_sats: value in sats to be deposited in the contract
/// @param coin_address: on-chain address of the coin owner
/// @param ecryption_commitment_scalar: commitment scalar used for Elgamal encryption of QQ Account and memo commitment
/// @param program_json_path: path to the json file containing the contract program
/// @param chain_net: Network address indicator i.e., Main or TestNet
/// @param state_variables: vector of state variables to be initialized
/// @param program_tag: tag of the program to be deployed   
/// @return transaction id
pub fn broadcast_contract_deploy_transaction(
    sk: RistrettoSecretKey,
    value_sats: u64,
    coin_address: String,
    ecryption_commitment_scalar: Scalar,
    program_json_path: &str,
    chain_net: Network, // Main / TestNet
    state_variables: Vec<u64>,
    program_tag: String,
) -> Result<String, String> {
    let tx = create_contract_deploy_transaction(
        sk,
        value_sats,
        coin_address,
        ecryption_commitment_scalar,
        program_json_path,
        chain_net,
        state_variables,
        program_tag,
    )?;
    tx_commit_broadcast_transaction(tx)
}

/// Creates a contract deploy transaction
/// @param sk: RistrettoSecretKey of the coin owner
/// @param value_sats: value in sats to be deposited in the contract
/// @param coin_address: on-chain address of the coin owner
/// @param ecryption_commitment_scalar: commitment scalar used for Elgamal encryption of QQ Account and memo commitment
/// @param program_json_path: path to the json file containing the contract program
/// @param chain_net: Network address indicator i.e., Main or TestNet
/// @param state_variables: vector of state variables to be initialized
/// @param program_tag: tag of the program to be deployed
/// @return transaction
pub fn create_contract_deploy_transaction(
    sk: RistrettoSecretKey,
    value_sats: u64,
    coin_address: String,
    ecryption_commitment_scalar: Scalar,
    program_json_path: &str,
    chain_net: Network, // Main / TestNet
    state_variables: Vec<u64>,
    program_tag: String,
) -> Result<Transaction, String> {
    // get the coin account from chain using coin address and create input coin
    let coin_input = get_transaction_coin_input_from_address(coin_address.clone())?;

    //get the programs to deployed for the contract from the given path
    let contract_manager = ContractManager::import_program(&program_json_path);
    // create the contract address
    let contract_address = contract_manager.create_contract_address(chain_net)?;

    //create OutputMemo corresponding to InputCoin
    let memo_output = create_memo_for_deployment(
        value_sats,
        contract_address.clone(),
        coin_address.clone(),
        ecryption_commitment_scalar,
    );
    // create input state and output state
    let (input_state, output_state) = create_state_for_deployment(
        value_sats,
        state_variables,
        contract_address.clone(),
        coin_address.clone(),
    );
    // create input and output vectors
    let input: Vec<Input> = vec![coin_input, input_state];
    let output: Vec<Output> = vec![memo_output, output_state];
    //create call proof for the contract initialization program
    // get the initialization program
    let initialization_program = contract_manager.get_program_by_tag(&program_tag)?;
    let call_proof = contract_manager.create_call_proof(chain_net, &program_tag)?;

    // create sk vector to sign on inputs and outputs
    let sk_list: Vec<RistrettoSecretKey> = vec![sk.clone(), sk.clone()];
    // create script transaction
    let script_tx = transaction::ScriptTransaction::create_script_transaction(
        &sk_list,
        initialization_program,
        call_proof,
        &input,
        &output,
        None,
        true,
        5u64,
    );
    match script_tx {
        Ok(tx) => {
            let tx = Transaction::transaction_script(TransactionData::TransactionScript(tx));
            Ok(tx)
        }
        Err(e) => Err(format!("Error at creating script transaction :{:?}", e).into()),
    }
}
/// creates input and output state for contract deployment
/// Input state is initialized as zero
/// Output State is initialized with the coin deposit values
/// @param value_sats: value in sats to be deposited in the contract
/// @param state_variables: vector of state variables to be initialized
/// @param contract_address: contract address
/// @param coin_address: on-chain address of the coin owner
/// @return input state and output state
pub fn create_state_for_deployment(
    value_sats: u64,
    state_variables: Vec<u64>,
    contract_address: String,
    coin_address: String,
) -> (Input, Output) {
    // create input state
    // Input state will be zero at initialization.
    let scalar_commitment = Scalar::random(&mut OsRng);

    // create zero value commitment. used for initializing TLV
    let zero_commitment = Commitment::blinded_with_factor(0, scalar_commitment);
    // create zero value state variables for initialization
    let mut in_state_var_vec: Vec<ZkvmString> = Vec::new();
    for _i in 0..state_variables.len() {
        let in_state_var = ZkvmString::Commitment(Box::new(zero_commitment.clone()));
        in_state_var_vec.push(in_state_var);
    }
    // create Input State
    let temp_out_state = OutputState {
        nonce: 0,
        script_address: contract_address.clone(),
        owner: coin_address.clone(),
        commitment: zero_commitment.clone(),
        state_variables: Some(in_state_var_vec),
        timebounds: 0,
    };
    // create zero proof vector for input state
    //stores witness for value commitment and state commitments
    //let zero_proof: Vec<Scalar> = vec![scalar_commitment; state_variables.len() + 1];

    // convert to input state
    let input_state: Input = Input::state(InputData::state(
        Utxo::default(), // utxo is zero for input state
        temp_out_state.clone(),
        None,
        1,
    ));

    // create output state using values from client
    // create value commitment
    let value_commitment = Commitment::blinded(value_sats);
    // create state variable commitments
    let mut s_var_vec: Vec<ZkvmString> = Vec::new();
    for i in 0..state_variables.len() {
        let s_var =
            ZkvmString::Commitment(Box::new(Commitment::blinded(state_variables[i].clone())));
        s_var_vec.push(s_var);
    }
    // create Output state
    let out_state: OutputState = OutputState {
        nonce: 1,
        script_address: contract_address.clone(),
        owner: coin_address.clone(),
        commitment: value_commitment.clone(),
        state_variables: Some(s_var_vec),
        timebounds: 0,
    };
    // create output from state
    let output: Output = Output::state(OutputData::State(out_state));
    //return input state, output state and zero proof
    (input_state, output)
}

/// creates output memo for contract deployment
/// @param initial_deposit: value in sats to be deposited in the contract
/// @param contract_address: contract address
/// @param coin_address: on-chain address of the coin owner
/// @param scalar_commitment: commitment scalar used for Elgamal encryption of QQ Account and memo commitment
/// @return output memo
pub fn create_memo_for_deployment(
    initial_deposit: u64,
    contract_address: String,
    coin_address: String,
    scalar_commitment: Scalar, // commitment scalar for encryption and commitment
) -> Output {
    // create output memo
    let script_address = contract_address.clone();
    let commit_memo = Commitment::blinded_with_factor(initial_deposit, scalar_commitment);
    let pool_share = Commitment::blinded(initial_deposit);
    let data = vec![ZkvmString::from(pool_share)];
    let memo_out = OutputMemo {
        script_address: script_address.clone(),
        owner: coin_address.clone(),
        commitment: commit_memo.clone(),
        data: Some(data),
        timebounds: 0,
    };
    let memo = Output::memo(OutputData::Memo(memo_out));
    memo
}
#[cfg(test)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused)]
mod test {

    use super::get_transaction_coin_input_from_address;
    use crate::util::*;
    use rand::rngs::OsRng;
    use zkvm::{program, Commitment};

    #[test]
    fn get_transaction_coin_input_from_address_test() {
        dotenv::dotenv().expect("Failed loading dotenv");
        let address="0c0a2555a4de4e44e9f10e8d682b1e63f58216ec3ae0d5947e6c65fd1efa952433e0a226db8e1ab54305ce578e39a305871ada6037e76a2ba74bc86e5c8011d736be751ed4".to_string();
        println!(
            "utxo_vec:{:?}",
            get_transaction_coin_input_from_address(address)
        );
    }

    #[test]
    fn create_chain_deploy_tx() {
        let seed = "UTQTkXOhF+D550+JW9A1rEQaXDtX9CYqbDOFqCY44S8ZYMoVzj8tybCB/Okwt+pblM0l3t9/eEJtfBpPcJwfZw==";
        let sk: quisquislib::ristretto::RistrettoSecretKey =
            quisquislib::keys::SecretKey::from_bytes(seed.as_bytes());
        println!("sk {:?}", sk);
        dotenv::dotenv().expect("Failed loading dotenv");

        // data for contract initialization
        let value_sats: u64 = 1000;
        let coin_address: String = "0c9ee2f0ef12a12745c0ad1111363f82134c426964ea2e985e6c3c3f7a0ee6d72b867e73d765be00ff4c8866ca142b3e3aa82dd75079b5ee514baf4e2ac7fc7e75f2daabc9".to_string();
        let commitment_scalar_hex =
            "af7362b6676c96883858eebaf721e981322a9327031fb62f928f8e688ca48704";
        let scalar_bytes = hex::decode(&commitment_scalar_hex).unwrap();
        let ecryption_commitment_scalar = curve25519_dalek::scalar::Scalar::from_bytes_mod_order(
            scalar_bytes.try_into().unwrap(),
        );
        //let ecryption_commitment_scalar = curve25519_dalek::scalar::Scalar::random(&mut OsRng);
        let program_json_path: &str = "./relayerprogram.json";
        let chain_net = address::Network::default();
        let state_variables: Vec<u64> = vec![1000];
        let program_tag: String = "RelayerInitializer".to_string();

        // create tx
        let tx = crate::script::create_contract_deploy_transaction(
            sk,
            value_sats,
            coin_address,
            ecryption_commitment_scalar,
            program_json_path,
            chain_net,
            state_variables,
            program_tag,
        );
        let verify = tx.clone().unwrap().verify();
        println!("verify:{:?}", verify);
        //convert tx to hex
        let tx_bin = bincode::serialize(&tx.unwrap()).unwrap();
        let tx_hex = hex::encode(&tx_bin);
        println!("tx_hex {:?}", tx_hex);
    }
}
