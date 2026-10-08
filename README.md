# LSM - Linux Security Monitor

A small Python tool that takes a snapshot of a Linux system's processes and network sockets, stores the process data in SQLite, and flags suspicious activity. I built it from scratch as a learning project.

## What it does

- Collects running processes with `ps -ef` and open sockets with `ss -tulpn`
- Parses the output into structured data (Python dicts)
- Saves each process snapshot to a SQLite database (`lsm.db`) with a timestamp, so history builds up over repeated runs
- Looks up each process's parent using its PPID
- Flags suspicious parent/child pairs from a configurable list (for example, a shell started by a web browser)
- Extracts the owning PID from the `ss` output with regex and links network connections to processes
- Assigns a risk level: **Medium** for a rule match, **High** if that process also has network activity
- Prints a summary of all findings at the end

## Requirements

- Linux with the `ps` and `ss` commands available
- Python 3 (standard library only, nothing to install)

## Usage

    python3 lsm.py

On a normal machine it prints nothing for processes that look fine. It only prints findings, plus a "no parent found" line for processes whose parent isn't in the snapshot (like PID 1).

## Limitations

- The suspicious-pair rules are a short hardcoded list in `suspicious_pairs`
- Only processes are stored in the database, not network connections
- Without root, `ss` only shows process info for your own sockets

## What I learned

Parsing command output in Python, SQLite and parameterized queries (and why they prevent SQL injection), regular expressions, and how to correlate two data sources.
