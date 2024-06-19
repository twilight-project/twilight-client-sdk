use crate::models::{AccountDB, NewAccount, NewOrder, OrderDB};
use crate::schema::{accounts, orders};
use diesel::pg::PgConnection;
use diesel::prelude::*;
use dotenv::dotenv;
use std::env;

pub fn establish_connection() -> PgConnection {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    PgConnection::establish(&database_url)
        .unwrap_or_else(|_| panic!("Error connecting to {}", database_url))
}

pub fn get_account_by_pk_address(
    address: &str,
    connection: &mut PgConnection,
) -> Result<AccountDB, diesel::result::Error> {
    use crate::schema::accounts::dsl::*;
    accounts
        .filter(pk_address.eq(address))
        .select(AccountDB::as_select())
        .first(connection)
}

pub fn get_account_by_id(
    idd: i32,
    connection: &mut PgConnection,
) -> Result<AccountDB, diesel::result::Error> {
    use crate::schema::accounts::dsl::*;
    accounts
        .find(idd)
        .select(AccountDB::as_select())
        .first(connection)
}

pub fn get_all_accounts(conn: &mut PgConnection) -> Result<Vec<AccountDB>, diesel::result::Error> {
    use crate::schema::accounts::dsl::*;
    accounts.load(conn)
}

pub fn get_accounts_with_null_scalar_str(
    conn: &mut PgConnection,
    limit: i64,
) -> Result<Vec<AccountDB>, diesel::result::Error> {
    use crate::schema::accounts::dsl::*;
    accounts
        .filter(scalar_str.is_null())
        .limit(limit)
        .load(conn)
}

pub fn get_all_accounts_with_not_null_scalar_str(
    conn: &mut PgConnection,
) -> Result<Vec<AccountDB>, diesel::result::Error> {
    use crate::schema::accounts::dsl::*;
    accounts.filter(scalar_str.is_not_null()).load(conn)
}

pub fn get_accounts_with_not_null_scalar_str(
    conn: &mut PgConnection,
    size: i64,
) -> Result<Vec<AccountDB>, diesel::result::Error> {
    use crate::schema::accounts::dsl::*;
    accounts
        .filter(scalar_str.is_not_null())
        .order(id.asc())
        .limit(size)
        .load(conn)
}
pub fn get_accounts_with_not_null_scalar_str_market(
    conn: &mut PgConnection,
    size: i64,
) -> Result<Vec<AccountDB>, diesel::result::Error> {
    use crate::schema::accounts::dsl::*;
    accounts
        .filter(scalar_str.is_not_null())
        .order(id.asc())
        .limit(size)
        .offset(100)
        .load(conn)
}

pub fn delete_account_by_pk_address(
    address: &str,
    conn: &mut PgConnection,
) -> Result<usize, diesel::result::Error> {
    use crate::schema::accounts::dsl::*;
    diesel::delete(accounts.filter(pk_address.eq(address))).execute(conn)
}

pub fn create_account(
    conn: &mut PgConnection,
    pk_address: &str,
    scalar_str: Option<&str>,
    is_on_chain: bool,
    balance: i32,
) -> Result<AccountDB, diesel::result::Error> {
    let new_account = NewAccount {
        pk_address,
        is_on_chain,
        scalar_str,
        balance,
    };

    diesel::insert_into(accounts::table)
        .values(&new_account)
        .returning(AccountDB::as_returning())
        .get_result(conn)
}

pub fn delete_account_by_id(
    idd: i32,
    conn: &mut PgConnection,
) -> Result<usize, diesel::result::Error> {
    use crate::schema::accounts::dsl::*;
    diesel::delete(accounts.filter(id.eq(idd))).execute(conn)
}

pub fn delete_all_accounts(conn: &mut PgConnection) -> Result<usize, diesel::result::Error> {
    use crate::schema::accounts::dsl::*;
    diesel::delete(accounts).execute(conn)
}

pub fn get_order_by_order_id_address(
    order_idd: &str,
    connection: &mut PgConnection,
) -> Result<OrderDB, diesel::result::Error> {
    use crate::schema::orders::dsl::*;
    orders
        .filter(order_id.eq(order_idd))
        .select(OrderDB::as_select())
        .first(connection)
}

pub fn get_order_by_id(
    idd: i32,
    connection: &mut PgConnection,
) -> Result<OrderDB, diesel::result::Error> {
    use crate::schema::orders::dsl::*;
    orders
        .find(idd)
        .select(OrderDB::as_select())
        .first(connection)
}

pub fn get_all_orders(conn: &mut PgConnection) -> Result<Vec<OrderDB>, diesel::result::Error> {
    use crate::schema::orders::dsl::*;
    orders.load(conn)
}

pub fn create_order(
    conn: &mut PgConnection,
    order_id: &str,
    order_type: &str,
    position_type: &str,
    order_status: &str,
    value: i64,
) -> Result<OrderDB, diesel::result::Error> {
    let new_order = NewOrder {
        order_id,
        order_type,
        position_type,
        order_status,
        value,
    };

    diesel::insert_into(orders::table)
        .values(&new_order)
        .returning(OrderDB::as_returning())
        .get_result(conn)
}

pub fn delete_order_by_id(
    idd: i32,
    conn: &mut PgConnection,
) -> Result<usize, diesel::result::Error> {
    use crate::schema::orders::dsl::*;
    diesel::delete(orders.filter(id.eq(idd))).execute(conn)
}

pub fn delete_all_orders(conn: &mut PgConnection) -> Result<usize, diesel::result::Error> {
    use crate::schema::orders::dsl::*;
    diesel::delete(orders).execute(conn)
}

pub fn get_orders_by_type(
    conn: &mut PgConnection,
    ord_type: &str,
    limit: i64,
) -> Result<Vec<OrderDB>, diesel::result::Error> {
    use crate::schema::orders::dsl::*;
    orders
        .filter(order_type.eq(ord_type))
        .order(id.asc())
        .limit(limit)
        .load(conn)
}

pub fn get_all_orders_by_status(
    conn: &mut PgConnection,
    ord_status: &str,
) -> Result<Vec<OrderDB>, diesel::result::Error> {
    use crate::schema::orders::dsl::*;
    orders.filter(order_status.eq(ord_status)).load(conn)
}

pub fn get_subset_order_by_status(
    conn: &mut PgConnection,
    ord_status: &str,
    size: i64,
) -> Result<Vec<OrderDB>, diesel::result::Error> {
    use crate::schema::orders::dsl::*;
    orders
        .filter(order_status.eq(ord_status))
        .order(id.asc())
        .limit(size)
        .load(conn)
}

pub fn get_orders_by_position_type(
    conn: &mut PgConnection,
    pos_type: &str,
) -> Result<Vec<OrderDB>, diesel::result::Error> {
    use crate::schema::orders::dsl::*;
    orders.filter(position_type.eq(pos_type)).load(conn)
}

// Update order status by order id
pub fn update_order_status_by_order_id(
    conn: &mut PgConnection,
    idd: i32,
    new_status: &str,
) -> Result<usize, diesel::result::Error> {
    use crate::schema::orders::dsl::*;
    diesel::update(orders.filter(id.eq(idd)).filter(order_status.eq("PENDING")))
        .set(order_status.eq(new_status))
        .execute(conn)
}
