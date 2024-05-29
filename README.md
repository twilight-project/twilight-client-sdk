# zkos-client-wallet
 

install diesel cli in the repository

cargo install diesel_cli
 or 
cargo install diesel_cli --no-default-features --features postgres


This will create a new DB named order_book_staging as defined in the .env file

run diesel setup

The migrations are already set up

run following to create tables
diesel migration run  

to recheck
diesel migration redo 

