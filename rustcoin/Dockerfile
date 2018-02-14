FROM rust:1.23

RUN mkdir -p /opt/rustcoin
RUN mkdir -p /opt/cargo
WORKDIR /opt/rustcoin
COPY . /opt/rustcoin

# CMD cargo run
CMD ./startup.sh