//! Handles the creation of ZkVM-based smart contract transactions.
//!
//! This module provides the high-level functions necessary to construct and prove
//! transactions that deploy and initialize smart contracts on the Twilight network.
//! It orchestrates the creation of inputs, outputs, and the required call proofs
//! for interacting with the ZkOS virtual machine.

use crate::{chain::*, programcontroller::ContractManager};
use address::Network;
use curve25519_dalek::scalar::Scalar;
use rand::rngs::OsRng;
use transaction::{quisquislib::ristretto::RistrettoSecretKey, Transaction, TransactionData};
use zkvm::{
    zkos_types::{Input, Output, OutputMemo, OutputState, Utxo},
    Commitment, InputData, OutputData, String as ZkvmString,
};

/// Creates a complete script transaction for deploying a new smart contract.
///
/// This function orchestrates the entire deployment process:
/// 1. Fetches the user's coin to be used for the initial deposit.
/// 2. Loads the contract programs from the specified JSON file.
/// 3. Creates the contract address from the programs' Merkle root.
/// 4. Generates the initial `OutputMemo` and state `Output` for the contract.
/// 5. Creates the `CallProof` required to run the contract's initialization program.
/// 6. Builds and signs the final script transaction.
///
/// # Parameters
/// - `sk`: The secret key of the account deploying the contract.
/// - `value_sats`: The initial amount in satoshis to deposit into the contract.
/// - `pool_share`: The initial pool share amount (if applicable for the contract).
/// - `coin_address`: The hex-encoded address of the deployer.
/// - `ecryption_commitment_scalar`: A random scalar for ElGamal encryption and commitments.
/// - `program_json_path`: The file path to the JSON file containing the contract's programs.
/// - `chain_net`: The target network (`Main` or `TestNet`).
/// - `state_variables`: A vector of initial values for the contract's state variables.
/// - `program_tag`: The tag of the initialization program to run upon deployment.
/// - `fee`: The transaction fee.
///
/// # Returns
/// A `Result` containing a tuple of the deploy `Transaction` and the new state `Output` on success,
/// or a string describing the error on failure.
pub fn create_contract_deploy_transaction(
    sk: RistrettoSecretKey,
    value_sats: u64,
    pool_share: u64,
    coin_address: String,
    ecryption_commitment_scalar: Scalar,
    program_json_path: &str,
    chain_net: Network,
    state_variables: Vec<u64>,
    program_tag: String,
    fee: u64,
) -> Result<(Transaction, Output), String> {
    // get the coin account from chain using coin address and create input coin
    let coin_input = get_transaction_coin_input_from_address(coin_address.clone())?;

    //get the programs to deployed for the contract from the given path
    let contract_manager = ContractManager::import_program(program_json_path);
    // create the contract address
    let contract_address = contract_manager.create_contract_address(chain_net)?;

    //create OutputMemo corresponding to InputCoin
    let memo_output = create_memo_for_deployment(
        value_sats,
        pool_share,
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
    let output: Vec<Output> = vec![memo_output, output_state.clone()];
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
        fee,
    );
    match script_tx {
        Ok(tx) => {
            let tx = Transaction::transaction_script(TransactionData::TransactionScript(tx));
            Ok((tx, output_state))
        }
        Err(e) => Err(format!("Error at creating script transaction :{:?}", e).into()),
    }
}

/// Creates the initial input and output state UTXOs for a contract deployment.
///
/// The `Input` state is always zeroed out, as a new contract has no prior state.
/// The `Output` state is initialized with the starting deposit value and any
/// other specified state variables, all committed to using random blinding factors.
///
/// # Parameters
/// - `value_sats`: The initial value to be deposited and committed to in the contract's state.
/// - `state_variables`: A vector of initial values for the contract's other state variables.
/// - `contract_address`: The hex-encoded address of the new contract.
/// - `coin_address`: The hex-encoded address of the owner/deployer.
///
/// # Returns
/// A tuple containing the `(Input, Output)` state UTXOs.
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
    (input_state, output)
}

/// Creates the `OutputMemo` for a contract deployment transaction.
///
/// This memo is a public record on the blockchain that contains commitments to the
/// initial deposit and other relevant data like pool shares.
///
/// # Parameters
/// - `initial_deposit`: The amount being deposited into the contract.
/// - `pool_share`: The initial pool share amount (if applicable).
/// - `contract_address`: The hex-encoded address of the new contract.
/// - `coin_address`: The hex-encoded address of the owner/deployer.
/// - `scalar_commitment`: A random scalar used for creating the value commitments.
///
/// # Returns
/// An `Output` struct containing the generated `OutputMemo`.
pub fn create_memo_for_deployment(
    initial_deposit: u64,
    pool_share: u64,
    contract_address: String,
    coin_address: String,
    scalar_commitment: Scalar,
) -> Output {
    // create output memo
    let script_address = contract_address.clone();
    let commit_memo = Commitment::blinded_with_factor(initial_deposit, scalar_commitment);
    let pool_share = Commitment::blinded_with_factor(pool_share, scalar_commitment);
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
    use address::{Address, Network};
    use curve25519_dalek::scalar::Scalar;
    use quisquislib::accounts::Account;
    use quisquislib::elgamal::ElGamalCommitment;
    use quisquislib::keys::{PublicKey, SecretKey};
    use quisquislib::ristretto::{RistrettoPublicKey, RistrettoSecretKey};
    use rand::rngs::OsRng;
    use transaction::vm_run::{Prover, Verifier};
    use zkvm::{program::Program, Commitment};
    use zkvm::{
        zkos_types::{InputData, OutputCoin, OutputMemo, OutputState, Utxo},
        Input, Output,
    };
    #[test]
    fn get_transaction_coin_input_from_address_test() {
        dotenvy::dotenv().expect("Failed loading dotenv");
        let address = std::env::var("TEST_ADDRESS")
            .expect("Failed to load TEST_ADDRESS environment variable.");
        println!(
            "utxo_vec:{:?}",
            get_transaction_coin_input_from_address(address)
        );
    }
    #[test]
    fn deploy_program_test() {
        let prog = Program::build(|p| {
            // TVL 0 and TPS0 are not pushed on stack. Zero value proof provided in witness
            p.commit()
                .expr() // TPS added to constraint
                .roll(2) // get PoolShare to top of stack
                .commit()
                .expr()
                .eq() // PoolShare == TPS
                .roll(1) //get TLV to top of stack
                .commit()
                .expr()
                .roll(2) //get Deposit to top of stack
                .commit()
                .expr()
                .eq() // Deposit == TLV
                .and() // PoolShare == TPS && Deposit == TLV
                .verify();
        });
        // create input coin
        let mut rng = rand::thread_rng();
        let sk_in: RistrettoSecretKey = SecretKey::random(&mut rng);
        let pk_in = RistrettoPublicKey::from_secret_key(&sk_in, &mut rng);
        let rscalar = Scalar::random(&mut rng);
        let commit_in = ElGamalCommitment::generate_commitment(
            &pk_in,
            rscalar.clone(),
            Scalar::from(100000000u64),
        );
        let coin_acc = Account::set_account(pk_in.clone(), commit_in.clone());
        let add: Address = Address::standard_address(Network::default(), pk_in.clone());
        let out_coin = OutputCoin {
            encrypt: commit_in.clone(),
            owner: add.as_hex(),
        };
        let in_data: InputData = InputData::coin(Utxo::default(), out_coin, 0);
        let coin_input: Input = Input::coin(in_data);
        //create OutputMemo corresponding to InputCoin
        let memo_output = crate::script::create_memo_for_deployment(
            100000000u64,
            10u64,
            add.as_hex(), // Should be contract address. Does not matter for this contract_address.clone(),
            add.as_hex().clone(),
            rscalar,
        );
        let state_variables: Vec<u64> = vec![10]; // TPS
                                                  // create input state and output state
        let (input_state, output_state) = crate::script::create_state_for_deployment(
            100000000u64,
            state_variables,
            add.as_hex().clone(),
            add.as_hex().clone(),
        );
        // create input and output vectors
        let input: Vec<Input> = vec![coin_input, input_state];
        let output: Vec<Output> = vec![memo_output, output_state.clone()];
        //cretae unsigned Tx with program proof
        let result = Prover::build_proof(prog, &input, &output, true, None);
        //i println!("{:?}", result);
        let (prog_bytes, proof) = result.unwrap();
        let verify = Verifier::verify_r1cs_proof(&proof, &prog_bytes, &input, &output, true, None);
        println!("Final Verify Result{:?}", verify);
    }
    #[test]
    fn create_chain_deploy_tx() {
        dotenvy::dotenv().expect("Failed loading dotenv");
        // Generate a test key for demonstration purposes - never use hardcoded seeds in production
        // Load RELAYER_SEED from .env
        let seed = std::env::var("RELAYER_SEED").expect("Failed to load RELAYER_SEED from .env");
        //derive private key;
        let sk = SecretKey::from_bytes(seed.as_bytes());

        // data for contract initialization
        let value_sats: u64 = 20000000000u64;
        let coin_address =
            std::env::var("TEST_COIN_ADDRESS").expect("Failed to load TEST_COIN_ADDRESS from .env");
        let commitment_scalar_hex = std::env::var("TEST_COMMITMENT_SCALAR")
            .expect("Failed to load TEST_COMMITMENT_SCALAR from .env");
        let encryption_commitment_scalar =
            crate::util::hex_to_scalar(commitment_scalar_hex.to_string()).unwrap();
        let program_json_path: &str = "./relayerprogram.json";
        let chain_net = address::Network::default();
        let state_variables: Vec<u64> = vec![2000000];
        let program_tag: String = "RelayerInitializer".to_string();
        let pool_share = 2000000u64;
        // create tx
        let tx = crate::script::create_contract_deploy_transaction(
            sk,
            value_sats,
            pool_share,
            coin_address,
            encryption_commitment_scalar,
            program_json_path,
            chain_net,
            state_variables,
            program_tag,
            1u64,
        );
        let (tx, out_state) = tx.unwrap();

        let verify = tx.clone().verify();
        println!("Verify Tx:{:?}", verify.is_ok());
        //convert tx to hex
        let tx_bin = bincode::serialize(&tx).unwrap();
        let tx_hex = hex::encode(&tx_bin);
        // convert output state to hex for broadcasting
        let out_state_bin = bincode::serialize(&out_state).unwrap();
        let out_state_hex = hex::encode(&out_state_bin);

        println!("tx_hex {:?}\n", tx_hex);
        println!("out_state_hex {:?}\n", out_state_hex);
    }
}
