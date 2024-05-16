use diesel::prelude::*;

#[derive(Insertable, Queryable, Identifiable, AsChangeset)]
#[table_name = "accounts"]
pub struct Account {
    pub address: String,
    pub is_on_chain: bool,
    pub scalar: String,
    pub tag: String,
    pub value: i32,
}

#[derive(Insertable, Queryable, Identifiable, AsChangeset)]
#[table_name = "orders"]
pub struct Order {
    pub account_id: String,
    pub datetime: String,
    pub id: i32,
    pub order_id: String,
    pub order_status: String,
    pub order_type: String,
    pub output: String,
    pub request_id: String,
    pub tx_hash: String,
    pub archived: bool,
}

pub fn insert_account(conn: &PgConnection, account: Account) -> QueryResult<usize> {
    diesel::insert_into(accounts::table)
        .values(&account)
        .execute(conn)
}

pub fn delete_account(conn: &PgConnection, account_address: String) -> QueryResult<usize> {
    diesel::delete(accounts::table.find(account_address))
        .execute(conn)
}

pub fn insert_order(conn: &PgConnection, order: Order) -> QueryResult<usize> {
    diesel::insert_into(orders::table)
        .values(&order)
        .execute(conn)
}

pub fn delete_order(conn: &PgConnection, order_id: i32) -> QueryResult<usize> {
    diesel::delete(orders::table.find(order_id))
        .execute(conn)
}

pub fn replace_account(conn: &PgConnection, old_address: String, new_account: Account) -> QueryResult<()> {
    conn.transaction(|| {
        diesel::update(orders::table.filter(orders::account_id.eq(&old_address)))
            .set((orders::account_id.eq(&new_account.address), orders::archived.eq(true)))
            .execute(conn)?;

        diesel::delete(accounts::table.find(old_address)).execute(conn)?;

        diesel::insert_into(accounts::table).values(&new_account).execute(conn)?;

        Ok(())
    })
}

pub fn get_orders_by_account_id_all(conn: &PgConnection, account_id: String) -> QueryResult<Vec<Order>> {
    orders::table.filter(orders::account_id.eq(account_id)).load::<Order>(conn)
}

pub fn get_orders_by_account_id(conn: &PgConnection, account_id: String) -> QueryResult<Vec<Order>> {
    orders::table
        .filter(orders::account_id.eq(account_id))
        .filter(orders::archived.eq(false))
        .load::<Order>(conn)
}

pub fn get_account_by_address(conn: &PgConnection, address: String) -> QueryResult<Account> {
    accounts::table.find(address).first::<Account>(conn)
}