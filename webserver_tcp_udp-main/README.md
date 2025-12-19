# Webserver DHT Testing Guide

This project contains a small HTTP server that can participate in a two-node
Chord-style DHT ring. The steps below show how to build the server and verify
hash-based routing between two nodes.

## Build

Use a fresh build directory to avoid stale CMake cache entries:

```sh
cmake -S . -B build
cmake --build build
```

The compiled binary will be available at `build/webserver`.

## Start a two-node ring

Open **two terminals** in `webserver_tcp_udp-main` and start each node with its
own IP/port and the predecessor/successor information provided via environment
variables. If you omit the optional third CLI argument, the node ID defaults to
`0`.

Terminal 1 (Node A):

```sh
PRED_ID=49152 PRED_IP=127.0.0.1 PRED_PORT=2002 \
SUCC_ID=49152 SUCC_IP=127.0.0.1 SUCC_PORT=2002 \
./build/webserver 127.0.0.1 2001 16384
```

Terminal 2 (Node B):

```sh
PRED_ID=16384 PRED_IP=127.0.0.1 PRED_PORT=2001 \
SUCC_ID=16384 SUCC_IP=127.0.0.1 SUCC_PORT=2001 \
./build/webserver 127.0.0.1 2002 49152
```

> In a two-node ring, each node is the other's predecessor and successor.

## Verify hashing and routing

Use `curl` to issue requests against either node. The server computes the
16‑bit pseudo-hash of the requested path and decides responsibility based on
its own ID range.

- Request a resource directly owned by the node: expect a `200 OK` response.
- Request a resource owned by the other node: expect a `303 See Other` redirect
  with the peer's address in the `Location` header.

Example (from a third terminal):

```sh
# Ask Node A for a resource; it may redirect to Node B if B owns the hash
curl -i http://127.0.0.1:2001/static/foo

# Follow redirects automatically
curl -i -L http://127.0.0.1:2001/static/foo
```

You can also use `PUT`/`DELETE` to modify resources on the responsible node and
repeat the `GET` to confirm the change.
