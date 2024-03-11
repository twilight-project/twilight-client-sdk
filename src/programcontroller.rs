//#![allow(dead_code)]
//#![allow(unused_imports)]
use address::{Address, Network};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::prelude::*;
use zkvm::merkle::CallProof;
pub type Tag = String;
use zkvm::encoding::Encodable;
use zkvm::{Hasher, MerkleTree, Program};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ContractManager {
    pub program_index: HashMap<Tag, usize>,
    pub program: Vec<String>,
}
impl ContractManager {
    pub fn new() -> Self {
        ContractManager {
            program_index: HashMap::new(),
            program: Vec::new(),
        }
    }

    pub fn add_program(&mut self, tag: &str, program: Program) -> Result<(), &'static str> {
        let encoded_program_data = program.encode_to_vec();
        let program_hex_encoded = hex::encode(encoded_program_data);
        if self.program_index.contains_key(tag) {
            Err("Program Tag already exist")
        } else {
            let len = self.program.len();
            self.program_index.insert(tag.to_string(), len);
            self.program.push(program_hex_encoded);
            Ok(())
        }
    }

    pub fn import_program(path: &str) -> ContractManager {
        let read_data = fs::read(path);
        let decode_data: ContractManager;

        match read_data {
            Ok(json_data_encode) => {
                decode_data = serde_json::from_slice(&json_data_encode).unwrap();
            }
            Err(arg) => {
                println!("No previous program Found- Error:{:#?}", arg);
                decode_data = ContractManager::new();
            }
        }

        decode_data
    }

    pub fn export_program(&self, path: &str) {
        let mut file = File::create(path).unwrap();
        file.write_all(&serde_json::to_vec_pretty(&self.clone()).unwrap())
            .unwrap();
    }

    pub fn get_program_by_tag(&self, tag: &str) -> Result<Program, &'static str> {
        match self.program_index.get(tag) {
            Some(index) => match hex::decode(self.program[*index].clone()) {
                Ok(program_bytes) => match Program::parse(&program_bytes) {
                    Ok(program) => Ok(program),
                    Err(_err) => Err("Program parsing error"),
                },
                Err(_) => Err("Program doesn't exist or hex invalid"),
            },
            None => Err("Program doesn't exist"),
        }
    }

    pub fn get_program_vec(&self) -> Result<Vec<Program>, &'static str> {
        let vec_program_len: usize = self.program.len();
        let mut programs: Vec<Program> = Vec::new();
        if vec_program_len > 0 {
            for program_hex in self.program.clone() {
                match hex::decode(program_hex) {
                    Ok(program_bytes) => match Program::parse(&program_bytes) {
                        Ok(program) => programs.push(program),
                        Err(_) => return Err("Program parsing error"),
                    },
                    Err(_) => return Err("Program doesn't exist or hex invalid"),
                }
            }

            Ok(programs)
        } else {
            Err("Program doesn't exist")
        }
    }
    pub fn create_call_proof(
        &self,
        network: Network,
        tag: &str,
    ) -> Result<CallProof, &'static str> {
        // create a tree of programs
        let hasher = Hasher::new(b"ZkOS.MerkelTree");
        //get vector of programs
        let progs_list = self.get_program_vec()?;

        //get the index of the tagged program
        match self.program_index.get(tag) {
            Some(index) => {
                let call_proof =
                    CallProof::create_call_proof(&progs_list, index.to_owned(), &hasher, network);

                match call_proof {
                    Some(cp) => Ok(cp),
                    None => Err("Call proof can not be created successfully"),
                }
            }
            None => Err("Program doesn't exist"),
        }
    }

    pub fn create_contract_address(&self, network: Network) -> Result<String, &'static str> {
        //get vector of programs
        let progs = self.get_program_vec()?;

        //create tree root
        let root = MerkleTree::root(b"ZkOS.MerkelTree", progs.iter());
        //convert root to address
        let address = Address::script_address(network, root.0);
        //script address as hex
        Ok(address.as_hex())
    }
}

#[cfg(test)]
#[allow(unused_imports)]
#[allow(dead_code)]
#[allow(unused)]
mod tests {
    use crate::programcontroller::*;
    use std::fs::File;
    use std::io::prelude::*;
    use zkvm::encoding::Encodable;
    use zkvm::Program;
    //Stack = Deposit in Sats -> Poolshare as whole number -> TLV0 = 0 -> TLV1 = Deposit -> TPS0 = 0 -> TPS1 = Poolshare
    // This program only works for PS as whole numbers
    fn relayer_contract_initialize_program() -> Program {
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
                .and()// PoolShare == TPS && Deposit == TLV
                .verify();
        });
        return prog;
    }
    // program to prove that IM * EntryPrice * Leverage == PositionSize
    // pub fn get_trader_order_program() -> Program {
    //     let order_prog = Program::build(|p| {
    //         p.drop() // drop the order_side from stack. Not needed in the proof
    //             .roll(3) // Get IM to top of stack
    //             .commit()
    //             .expr()
    //             .roll(1) // Get EntryPrice to top of stack
    //             .scalar()
    //             .mul() // EntryPrice * IM
    //             .roll(1) // Get Leverage to top of stack
    //             .commit()
    //             .expr()
    //             .mul() // Leverage * EntryPrice * IM
    //             .roll(1)
    //             .scalar()
    //             .eq() // Leverage * EntryPrice * IM == PositionSize
    //             .verify();
    //     });
    //     return order_prog;
    // }

    // program to prove IM * Leverage = positionvalue
    // Stack -> C(IM) -> PositionSize-> C(Leverage) -> EntryPrice -> OrderSide -> tx_Data(C(PositionValue))
      pub fn get_trader_order_program() -> Program {
        let order_prog = Program::build(|p| {
            p.roll(3) // Get Leverage to top of stack
                .commit()
                .expr()
                .roll(5) // Get IM to top of stack
                .commit()
                .expr() 
                .mul() // IM * Leverage
                .eq() // Leverage * IM == PositionValue
                .verify()
                .drop()// drop orderSide
                .drop() // drop EntryPrice
                .drop(); // drop PositionSize    
        });
        order_prog
    }

    pub fn get_settle_trader_order_program() -> Program {
        let settle_prog = Program::build(|p| {
            p.roll(3) //drop TPS1
                .drop()
                .roll(3)
                .drop() //drop TPS0
                .roll(10) // Get IM to top of stack
                .commit()
                .dup(0) // duplicate IM
                .expr()
                .neg() // -IM
                .roll(7) // Get AM to top of stack
                .commit()
                .dup(0) // duplicate AM
                .expr()
                .roll(2) // get -IM to top
                .add() // AM - IM = Payment
                .roll(2) // get IM
                .expr()
                .neg() // -IM
                .roll(2) //get AM
                .expr()
                .add() //AM -IM
                .roll(4) //marginDifference
                .commit()
                .expr()
                .neg() // -mD
                .add() // AM - IM - mD
                .dup(2) //duplicate  SettlePrice
                .scalar()
                .mul() // SettlePrice * (AM - IM - mD)
                .dup(7) //duplicate entryprice
                .scalar()
                .mul() // EntryPrice * SettlePrice * (AM - IM - mD)
                .roll(7) // get EntryPrice
                .scalar()
                .roll(3) //get SettlePrice
                .scalar()
                .neg() //-settlePrice
                .add() // entryPrice - settlePrice
                .roll(6) // get Order Side (-1 for Long / 1 for short)
                .scalar()
                .mul() // OrderSide * (EntryPrice - SettlePrice)
                .roll(7) // get PositionSize
                .scalar()
                .mul() // PositionSize * OrderSide * (EntryPrice - SettlePrice)
                .roll(3) //get Error
                .scalar()
                .add() // Error + PositionSize * OrderSide * (EntryPrice - SettlePrice)
                .eq() //(Payment - marginDifference)*EntryPrice*SettlePrice = Error + PositionSize * OrderSide * (EntryPrice - SettlePrice)
                .roll(1) // get Payment = AM - IM as expression
                .neg()
                .roll(3) //get TVL0
                .commit()
                .expr()
                .add() //TVL0 - Payment
                .roll(2) // get TVL1
                .commit()
                .expr()
                .eq() // TVL1 = TVL0 - Payment
                .and() // Bind both constraints
                .verify()
                .drop(); // drop leverage
        });
        return settle_prog;
    }

     pub fn get_settle_trader_order_negative_margin_difference_program() -> Program {
        let settle_prog = Program::build(|p| {
            p.roll(3) //drop TPS1
                .drop()
                .roll(3)
                .drop() //drop TPS0
                .roll(10) // Get IM to top of stack
                .commit()
                .dup(0) // duplicate IM
                .expr()
                .neg() // -IM
                .roll(7) // Get AM to top of stack
                .commit()
                .dup(0) // duplicate AM
                .expr()
                .roll(2) // get -IM to top
                .add() // AM - IM = Payment
                .roll(2) // get IM
                .expr()
                .neg() // -IM
                .roll(2) //get AM
                .expr()
                .add() //AM -IM
                .roll(4) //marginDifference
                .commit()
                .expr()
                //.neg() // -mD
                .add() // AM - IM + mD
                .dup(2) //duplicate  SettlePrice
                .scalar()
                .mul() // SettlePrice * (AM - IM + mD)
                .dup(7) //duplicate entryprice
                .scalar()
                .mul() // EntryPrice * SettlePrice * (AM - IM + mD)
                .roll(7) // get EntryPrice
                .scalar()
                .roll(3) //get SettlePrice
                .scalar()
                .neg() //-settlePrice
                .add() // entryPrice - settlePrice
                .roll(6) // get Order Side (-1 for Long / 1 for short)
                .scalar()
                .mul() // OrderSide * (EntryPrice - SettlePrice)
                .roll(7) // get PositionSize
                .scalar()
                .mul() // PositionSize * OrderSide * (EntryPrice - SettlePrice)
                .roll(3) //get Error
                .scalar()
                .add() // Error + PositionSize * OrderSide * (EntryPrice - SettlePrice)
                .eq() //(Payment - marginDifference)*EntryPrice*SettlePrice = Error + PositionSize * OrderSide * (EntryPrice - SettlePrice)
                .roll(1) // get Payment = AM - IM as expression
                .neg()
                .roll(3) //get TVL0
                .commit()
                .expr()
                .add() //TVL0 - Payment
                .roll(2) // get TVL1
                .commit()
                .expr()
                .eq() // TVL1 = TVL0 - Payment
                .and() // Bind both constraints
                .verify()
                .drop(); // drop leverage
        });
        return settle_prog;
    }


    pub fn lend_order_deposit_program() -> Program {
        let lend_order_prog = Program::build(|p| {
            // TPS1 - TPS0 = PS or TPS1 = PS + TPS0
            p.roll(1) //TPS1
                .commit()
                .expr()
                .dup(2) // TPS0
                .commit()
                .expr()
                .dup(6) // nPoolshare
                .commit()
                .expr()
                .add() //
                .eq() //  TPS0 + nPoolShare = TPS1
                .roll(3) //TLV1
                .commit()
                .expr()
                .dup(4) //TLV0
                .commit()
                .expr()
                .dup(7) // Deposit
                .commit()
                .expr()
                .add() //Deposit + tlv
                .eq() // TLV1 = Deposit + TLV0
                .and() // TPS== &&  TLV== &&
                .roll(1) // error
                .scalar()
                .roll(2) // TPS0
                .commit()
                .expr()
                .roll(5) //Deposit
                .commit()
                .expr()
                .mul() //Deposit * TPS0
                .add() // Deposit * TPS0 + error
                .roll(2) // TVL0
                .commit()
                .expr()
                .roll(3) // nPoolshare
                .commit()
                .expr()
                .mul() // TVL0 * nPoolshare
                .eq()
                .and()
                .verify();
        });
        return lend_order_prog;
    }

    pub fn lend_order_settle_program() -> Program {
        let lend_settle_prog = Program::build(|p| {
            // TPS1 - TPS0 = PS or TPS1 = PS + TPS0
            p.scalar() // Error
                //.neg() // -Error
                .dup(4) //TLV0
                .commit()
                .expr()
                .dup(7) // nPoolShare
                .commit()
                .expr()
                .mul() //nPoolShare * TLV0
                .add() // nPoolShare * TLV0 - Error
                .dup(2) // TPS0
                .commit()
                .expr()
                .dup(6) // nWithdraw
                .commit()
                .expr()
                .mul() // TPS0 * nWithdraw
                .eq() //  TPS0 * nWithdraw = nPoolShare * TLV0 + Error
                .roll(6) //nPoolShare
                .commit()
                .expr()
                .neg() // -nPoolShare
                .roll(3) //TPS0
                .commit()
                .expr()
                .add() // TPS0 -nPoolShare
                .roll(2) //TPS1
                .commit()
                .expr()
                .eq() //  TPS1 = TPS0 - nPoolShare
                .and() // Adding 2 Equalities together
                .roll(1) //TVL1
                .commit()
                .expr()
                .roll(2) //TVL0
                .commit()
                .expr()
                .roll(3) //nWithdraw
                .commit()
                .expr()
                .neg()
                .add() // TLV0- nWithdraw
                .eq() // TLV1 = TLV0 - nWithdraw
                .and() // rolling all constraints together
                .verify()
                .drop();
        });
        return lend_settle_prog;
    }
      pub fn get_liquidate_order_program() -> Program {
        let prog = Program::build(|p| {
                p.drop() //drop settle_price
                .drop()   //drop mD
                .drop() //error
                .drop() //TPS1
                .drop( ) //drop TPS0
                .commit() //commit on TVL1
                .expr()
                .roll(1) //get TVL0
                .commit()
                .expr()
                .roll(7) // Get IM to top of stack
                .commit()
                .expr()
                .add( ) //TVL0 + IM
                .eq() // TVL1 = TVL0 + IM
                .verify()
                .drop() // drop leverage
                .drop()
                .drop()
                .drop()
                .drop();
        });
        prog
    }
        
    #[test]
    fn load_relayer_contract_program_into_json() {
        let mut contract_manager = ContractManager::new();
        let path = "./relayerprogram.json";
        contract_manager.add_program(
            "RelayerInitializer",
            relayer_contract_initialize_program(),
        );

        contract_manager.add_program("CreateTraderOrder", get_trader_order_program());
        contract_manager.add_program("SettleTraderOrder", get_settle_trader_order_program());
        contract_manager.add_program("CreateLendOrder", lend_order_deposit_program());
        contract_manager.add_program("SettleLendOrder", lend_order_settle_program());
        contract_manager.add_program("LiquidateOrder", get_liquidate_order_program());
        contract_manager.add_program("SettleTraderOrderNegativeMarginDifference", get_settle_trader_order_negative_margin_difference_program());
        contract_manager.export_program(path);
    }

    #[test]
    fn add_program_test() {
        let path = "./relayerprogram.json";
        let tag = "Tag4";
        let program_code = relayer_contract_initialize_program();
        let mut programs = ContractManager::import_program(path);
        programs.add_program(tag, program_code).unwrap();
        programs.export_program(path);
    }
    #[test]
    fn import_program_test() {
        let path = "./relayerprogram.json";
        let data = ContractManager::import_program(path);
        println!("ContractManager:{:?}", data);
    }
    #[test]
    fn encode_program_test() {
        let program_data = relayer_contract_initialize_program();
        // let mut writer: Vec<u8>;
        let mut encoded_program_data = program_data.encode_to_vec();
        let program_hex = hex::encode(encoded_program_data);
        let decode_hex: Vec<u8> = hex::decode(program_hex).unwrap();

        let decoded_program_data: Program = Program::parse(&decode_hex).unwrap();
        println!("pro: {:?}", decoded_program_data);
    }

    #[test]
    fn get_program_by_tag_test() {
        let path = "./relayerprogram.json";
        let tag = "CreateTraderOrder";
        let programs = ContractManager::import_program(path);
        let single_program = programs.get_program_by_tag(tag);
        println!("program:tag1 : {:?}", single_program.unwrap())
    }
    #[test]
    fn get_program_in_vec_test() {
        let path = "./relayerprogram.json";
        let programs = ContractManager::import_program(path);
        let single_program = programs.get_program_vec();
        println!("program_vec : {:?}", single_program.unwrap());
    }
    #[test]
    fn create_contract_address_test() {
        let path = "./relayerprogram.json";
        let programs = ContractManager::import_program(path);
        let contract_address = programs.create_contract_address(Network::default());
        println!("address : {:?}", contract_address);
    }
    #[test]
    fn create_call_proof_test() {
        let path = "./relayerprogram.json";
        let programs = ContractManager::import_program(path);
        let call_proof: Result<CallProof, &str> =
            programs.create_call_proof(Network::default(), "CreateTraderOrder");
        println!("call_proof : {:?}", call_proof);
        // verify call proof
        //create tree root
        let progs = programs.get_program_vec().unwrap();
        let root = MerkleTree::root(b"ZkOS.MerkelTree", progs.iter());
        //convert root to address
        let address = Address::script_address(Network::default(), root.0);
        //script address as hex
        let address_hex = address.as_hex();
        // get program for CreateTraderOrder
        let prog_index = programs.program_index.get("CreateTraderOrder").unwrap();
        // get program at index
        let program_hex = programs.program[*prog_index].clone();
        let decode_hex: Vec<u8> = hex::decode(program_hex).unwrap();

        let decoded_program_data: Program = Program::parse(&decode_hex).unwrap();
        let hasher = Hasher::new(b"ZkOS.MerkelTree");

        // verify call proof
        let verify =
            call_proof
                .unwrap()
                .verify_call_proof(address_hex, &decoded_program_data, &hasher);
        println!("verify: {:?}", verify);
    }
}
