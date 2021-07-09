# barp
An eBPF based tool for establishing ARP-based covert channels, for JHU 695.722 Covert Channels.

## Demonstration

![https://youtu.be/jG3qZWfgDv4](https://youtu.be/jG3qZWfgDv4)

## Build Requirements

*  Docker and docker-compose
*  Vagrant

## Building

First, you must build the classifier. 

```
$ cd bpf/
$ docker-compose build
$ docker-compose run --rm filter-builder
$ cd ..
```
This will create the `filter_program_x86_64` program object file in the `bpf/` directory.
Then, you can build the program itself in a Linux VM.

```
$ vagrant up && vagrant ssh
$ cd barp/
$ cargo build
$ cd target/debug
$ ./barp
```

# Licenses

All Rust code here is distributed under the MIT license. 

The BPF filter program source (`bpf/filter.c`) and subsequent artifacts are distributed under dual MIT/GPL.

