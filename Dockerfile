FROM ubuntu:24.04

ARG CIFUZZ_TOKEN

RUN apt-get update && \
    apt-get install -y bison libssl-dev libevent-dev openssl curl cmake clang build-essential llvm lldb git pkg-config ninja-build zip unzip tar yacc lcov vim

RUN sh -c "$(curl -fsSL http://downloads.code-intelligence.com/assets/install-cifuzz.sh)" $CIFUZZ_TOKEN

RUN git clone   --recursive --branch cifuzz https://github.com/CodeIntelligenceTesting/openiked-portable.git
WORKDIR openiked-portable
RUN cmake --preset "cifuzz (Fuzzing)"
RUN cmake --preset "cifuzz (Coverage)"