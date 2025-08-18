// @generated automatically by Diesel CLI.

diesel::table! {
    accounts (id) {
        id -> Int4,
        #[max_length = 255]
        pk_address -> Varchar,
        is_on_chain -> Bool,
        #[max_length = 255]
        scalar_str -> Nullable<Varchar>,
        balance -> Int4,
    }
}

diesel::table! {
    orders (id) {
        id -> Int4,
        #[max_length = 255]
        order_id -> Varchar,
        #[max_length = 50]
        order_type -> Varchar,
        #[max_length = 50]
        position_type -> Varchar,
        #[max_length = 50]
        order_status -> Varchar,
        value -> Int8,
    }
}

diesel::allow_tables_to_appear_in_same_query!(
    accounts,
    orders,
);
