use diesel::prelude::*;
use crate::schema::{accounts, orders};

#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = crate::schema::accounts)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AccountDB {
    pub id: i32,
    pub pk_address: String,
    pub is_on_chain: bool,
    pub scalar_str: Option<String>,
    pub balance: i32,
}

impl AccountDB {
    pub fn get_balance(&self) -> i32 {
        self.balance
    }
    
}

#[derive(Insertable)]
#[diesel(table_name = accounts)]
pub struct NewAccount<'a> {
    pub pk_address: &'a str,
    pub is_on_chain: bool, 
    pub scalar_str: &'a str,
    pub balance: i32,
}


#[derive(Queryable, Selectable, Debug, Clone)]
#[diesel(table_name = crate::schema::orders)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct OrderDB {
    pub id: i32,
    pub order_id: String,
    pub order_type: String,
    pub position_type: String,
    pub order_status: String,
    pub value: i64,
}
impl OrderDB {
    pub fn get_value(&self) -> i64 {
        self.value
    }
    
}

#[derive(Insertable)]
#[diesel(table_name = orders)]
pub struct NewOrder<'a> {
    pub order_id: &'a str,
    pub order_type: &'a str,
    pub position_type: &'a str,
    pub order_status: &'a str,
    pub value: i64,
}





