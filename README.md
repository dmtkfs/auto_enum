# auto_enum

`auto_enum.py` is a one-shot, opinionated wrapper that chains together a
handful of well-known offensive-security tools — **Nmap, Gobuster, ffuf,
curl, Hydra, and sqlmap** — into a single asynchronous “fire-and-forget”
recon pipeline.

> **⚠️ DISCLAIMER**  
> This project is provided *as-is* for educational and personal-testing
> purposes **only**. The author accepts **no responsibility** for any
> damage, legal trouble, or unicorn stampedes that may result from its
> use. Always get **explicit permission** before pointing it at systems
> you do not own.

---

## Features

* Two-line sticky status bar (TTY and non-TTY friendly)  
* Recursive directory / file discovery with Gobuster  
* Parameter & file fuzzing with ffuf  
* Quick LFI/RCE/SQLi heuristics with curl  
* Hydra micro-brute for SSH and web forms  
* Optional sqlmap “micro pass” once SQLi is suspected  
* Ctrl-C quality-of-life: **single tap = skip current command; double
  tap within 1 s = exit script**

## Requirements

* Python 3.9+ with `asyncio` (std lib)
* External binaries in `$PATH`:
  `nmap gobuster ffuf curl hydra sqlmap`
* Linux/Mac or recent Windows 10+ (tested via WSL & PowerShell)

## Quick start

```bash
pipx install gobuster ffuf hydra  # or your package manager
python3 auto_enum.py 10.10.11.123 -D -S
````

Common flags:

| Flag   | Purpose                                             | Default |
| ------ | --------------------------------------------------- | ------- |
| `-t N` | global async concurrency                            | **8**   |
| `-D`   | “deeper” preset (more recursion & endpoints)        | off     |
| `-S`   | force sqlmap pass even w/out SQLi signal            | off     |
| `-R`   | use **rockyou.txt** for Hydra instead of quick list | off     |

Run `python3 auto_enum.py -h` for the full list.

---

## Contributing

This is a personal playground; PRs are welcome but may be merged slowly
(or not at all). Issues & feature suggestions are appreciated.

## License

See **[LICENSE](LICENSE)** — short version: MIT for *this* wrapper; each
underlying tool retains its own license.
