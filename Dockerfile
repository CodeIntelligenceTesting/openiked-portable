FROM ubuntu:22.04

ARG CIFUZZ_TOKEN

RUN apt-get update && \
    apt-get install -y bison libssl-dev libevent-dev openssl curl clang build-essential llvm lldb git pkg-config ninja-build zip unzip tar yacc lcov vim

RUN apt-get install -y software-properties-common lsb-release ca-certificates apt-transport-https gnupg curl
RUN curl -s https://apt.kitware.com/keys/kitware-archive-latest.asc | gpg --dearmor -o /usr/share/keyrings/kitware-archive-keyring.gpg  && \
    echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/kitware.list && \
    apt-get update && \
    apt-get install -y cmake

RUN sh -c "$(curl -fsSL http://downloads.code-intelligence.com/assets/install-cifuzz.sh)" $CIFUZZ_TOKEN

RUN git clone   --recursive --branch cifuzz https://github.com/CodeIntelligenceTesting/openiked-portable.git
WORKDIR openiked-portable
RUN cmake --preset "cifuzz (Fuzzing)"
RUN cmake --preset "cifuzz (Coverage)"