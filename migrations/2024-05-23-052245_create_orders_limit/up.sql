-- Your SQL goes here
CREATE TABLE orders (
  id SERIAL PRIMARY KEY, 
  order_id VARCHAR(255) NOT NULL,
  order_type VARCHAR(50) NOT NULL,
  position_type VARCHAR(50) NOT NULL,
  order_status VARCHAR(50) NOT NULL,
  value BIGINT NOT NULL DEFAULT 0
)