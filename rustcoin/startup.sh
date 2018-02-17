set -e

mkdir -p /opt/users/first
mkdir -p /opt/users/second
mkdir -p /opt/users/third

# cargo run &
# HOME=/opt/users/first PORT=8334 cargo run &
# HOME=/opt/users/second PORT=8335 cargo run &
# HOME=/opt/users/third PORT=8336 cargo run
cargo build --release

/opt/rustcoin/target/release/rustcoin &
HOME=/opt/users/first PORT=8334 /opt/rustcoin/target/release/rustcoin &
HOME=/opt/users/second PORT=8335 /opt/rustcoin/target/release/rustcoin &
HOME=/opt/users/third PORT=8336 /opt/rustcoin/target/release/rustcoin