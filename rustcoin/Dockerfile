FROM rust:1.23

RUN apt-get update
RUN apt-get install tcpdump -y

RUN mkdir -p /opt/rustcoin
RUN mkdir -p /opt/cargo
WORKDIR /opt/rustcoin
COPY . /opt/rustcoin

# RUN cargo build --release
# CMD cargo run
CMD ./startup.sh

