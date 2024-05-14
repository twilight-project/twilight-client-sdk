CREATE TABLE accounts (
    address TEXT PRIMARY KEY,
    is_on_chain BOOLEAN NOT NULL,
    scalar TEXT NOT NULL,
    tag TEXT NOT NULL,
    value INTEGER NOT NULL
);

CREATE TABLE orders (
    account_id TEXT REFERENCES accounts(address),
    datetime TEXT NOT NULL,
    id SERIAL PRIMARY KEY,
    order_id TEXT NOT NULL,
    order_status TEXT NOT NULL,
    order_type TEXT NOT NULL,
    output TEXT NOT NULL,
    request_id TEXT NOT NULL,
    tx_hash TEXT NOT NULL,
    archived BOOLEAN NOT NULL DEFAULT FALSE
);