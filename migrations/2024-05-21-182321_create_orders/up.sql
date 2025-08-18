-- Your SQL goes here
CREATE TABLE accounts (
  id SERIAL PRIMARY KEY,
  pk_address VARCHAR(255) NOT NULL,
  is_on_chain BOOLEAN NOT NULL DEFAULT FALSE,
  scalar_str VARCHAR(255),
  balance INT NOT NULL DEFAULT 0
 
)