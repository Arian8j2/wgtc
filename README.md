# wgtc

`wgtc` is a WireGuard traffic controller for Linux. It loads eBPF TC
classifiers on a WireGuard interface and applies bandwidth limits per peer IP.

Use it when one WireGuard server must give each peer a fixed ingress rate, a
fixed egress rate, or both.

## Features

- Limit WireGuard peer traffic with eBPF and Linux TC.
- Set ingress and egress limits independently.
- Track rate state per IPv4 peer address.
- Limit only TCP or UDP traffic when you set `--protocol`.

## Usage

Run `wgtc` on the WireGuard interface. Keep the process running while you want
the limits to stay active.

Limit peer download traffic to 50 Mbit/s and peer upload traffic to 10 Mbit/s:

```sh
sudo ./wgtc -i wg0 --ingress 50 --egress 10
```

## Requirements

- Linux with eBPF TC support.
- Each WireGuard peer must be assigned a unique /32 IPv4 address
- Root privileges, or equivalent privileges to load eBPF programs and attach TC
  classifiers.

