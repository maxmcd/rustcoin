mkdir -p /opt/users/first
mkdir -p /opt/users/second
mkdir -p /opt/users/third

cargo run &
HOME=/opt/users/first PORT=8334 cargo run &
HOME=/opt/users/second PORT=8335 cargo run &
HOME=/opt/users/third PORT=8336 cargo run