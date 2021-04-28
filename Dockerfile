FROM rust:latest

RUN apt-get update && apt-get install -y gcc-multilib

VOLUME /usr/src/kaminsky

WORKDIR /usr/src/kaminsky

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y -t i686-unknown-linux-musl

CMD ["cargo", "build", "--release", "--target", "i686-unknown-linux-musl"]
