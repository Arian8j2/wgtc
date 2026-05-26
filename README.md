# WireGuard eBPF Bandwidth Policer

An eBPF-based bandwidth policer for WireGuard interfaces.

This project attaches an eBPF program to a WireGuard interface and enforces ingress and egress bandwidth limits on a per-peer basis with configurable burst handling.

## Features

- Per-peer bandwidth policing
- Separate ingress and egress limits
- Low-overhead kernel-space packet processing
