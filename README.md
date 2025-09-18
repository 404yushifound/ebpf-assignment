# ebpf-assignment
Solutions to Accuknox eBPF assignment Problem 1 and Problem 2.
# eBPF Assignment (Simulation in Go)

This repository contains a **Go simulation** of the eBPF packet filtering assignment.

## Problem Statements
1. Drop TCP packets on port `4040`.  
2. Drop traffic for a specific process (`myprocess`) on all ports except `4040`.

## How It Works
Since native eBPF is kernel-level and not always easy to run in all environments,  
this project simulates packet filtering logic in **Go**:

- Drops packets destined to port `4040`.
- Drops all traffic for process `myprocess`, except at allowed ports.
- Prints whether packets are **allowed** or **dropped**.

## Run the Program
```bash
go run main.go

