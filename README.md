<p align="center">
  <a href="https://trezoa.xyz">
    <img alt="Trezoa-team" src="https://i.postimg.cc/VkKTnMM9/trezoa-logo-talc-1.png" width="250" />
  </a>
</p>

[![Trezoa crate](https://img.shields.io/crates/v/trezoa-core.svg)](https://crates.io/crates/trezoa-core)
[![Trezoa documentation](https://docs.rs/trezoa-core/badge.svg)](https://docs.rs/trezoa-core)
[![Build status](https://badge.buildkite.com/8cc350de251d61483db98bdfc895b9ea0ac8ffa4a32ee850ed.svg?branch=master)](https://buildkite.com/trezoa-team/trezoa/builds?branch=master)
[![codecov](https://codecov.io/gh/trezoa-team/trezoa/branch/master/graph/badge.svg)](https://codecov.io/gh/trezoa-team/trezoa)

# Building

## **1. Install rustc, cargo and rustfmt.**

```bash
$ curl https://sh.rustup.rs -sSf | sh
$ source $HOME/.cargo/env
$ rustup component add rustfmt
```

When building the master branch, please make sure you are using the latest stable rust version by running:

```bash
$ rustup update
```

When building a specific release branch, you should check the rust version in `ci/rust-version.sh` and if necessary, install that version by running:
```bash
$ rustup install VERSION
```
Note that if this is not the latest rust version on your machine, cargo commands may require an [override](https://rust-lang.github.io/rustup/overrides.html) in order to use the correct version.

On Linux systems you may need to install libssl-dev, pkg-config, zlib1g-dev, protobuf etc.

On Ubuntu:
```bash
$ sudo apt-get update
$ sudo apt-get install libssl-dev libudev-dev pkg-config zlib1g-dev llvm clang cmake make libprotobuf-dev protobuf-compiler libclang-dev
```

On Fedora:
```bash
$ sudo dnf install openssl-devel systemd-devel pkg-config zlib-devel llvm clang cmake make protobuf-devel protobuf-compiler perl-core libclang-dev
```

## **2. Download the source code.**

```bash
$ git clone https://github.com/trezoa-xyz/trezoa.git
$ cd trezoa
```

## **3. Build.**

```bash
$ ./cargo build
```

> [!NOTE]
> Note that this builds a debug version that is **not suitable for running a testnet or mainnet validator**. Please read [`docs/src/cli/install.md`](docs/src/cli/install.md#build-from-source) for instructions to build a release version for test and production uses.

# Testing

**Run the test suite:**

```bash
$ ./cargo test
```

### Starting a local testnet

Start your own testnet locally, instructions are in the [online docs](https://docs.trezoa.xyz/clusters/benchmark).

### Accessing the remote development cluster

* `devnet` - stable public cluster for development accessible via
devnet.trezoa.com. Runs 24/7. Learn more about the [public clusters](https://docs.trezoa.xyz/clusters)

# Benchmarking

First, install the nightly build of rustc. `cargo bench` requires the use of the
unstable features only available in the nightly build.

```bash
$ rustup install nightly
```

Run the benchmarks:

```bash
$ cargo +nightly bench
```

# Release Process

The release process for this trezoa is described [here](RELEASE.md).

# Code coverage

To generate code coverage statistics:

```bash
$ scripts/coverage.sh
$ open target/cov/lcov-local/index.html
```

Why coverage? While most see coverage as a code quality metric, we see it primarily as a developer
productivity metric. When a developer makes a change to the codebase, presumably it's a *trzution* to
some problem.  Our unit-test suite is how we encode the set of *problems* the codebase trzves. Running
the test suite should indicate that your change didn't *infringe* on anyone else's trzutions. Adding a
test *protects* your trzution from future changes. Say you don't understand why a line of code exists,
try deleting it and running the unit-tests. The nearest test failure should tell you what problem
was trzved by that code. If no test fails, go ahead and submit a Pull Request that asks, "what
problem is trzved by this code?" On the other hand, if a test does fail and you can think of a
better way to trzve the same problem, a Pull Request with your trzution would most certainly be
welcome! Likewise, if rewriting a test can better communicate what code it's protecting, please
send us that patch!
