# Security Policy

## Status

This project is unaudited and intended for learning and demonstration. It should not be used to protect real assets or data. Even so, reports of correctness or security problems are welcome and will be taken seriously.

## Reporting a vulnerability

Please report issues privately through GitHub's [private vulnerability reporting](https://github.com/apayne185/smart-contracts-DApp-dev/security/advisories/new) rather than opening a public issue.

Helpful details include:

- the affected component (for example `cpp/mlkem`, `contracts/TicketOffice.sol`)
- the commit hash you tested against
- steps or a test case that reproduces the problem
- the impact you expect (key recovery, signature forgery, fund loss, and so on)

You can expect an acknowledgement within one week.

## Scope

Particularly relevant findings include:

- deviations from FIPS 202, 203, or 205 that affect interoperability or security
- secret-dependent branches or memory access in ML-KEM or SLH-DSA
- memory-safety bugs in any C++ component
- smart contract issues that allow theft or locking of funds, unauthorised ticket transfer, or bypassing access control

Power, electromagnetic, and fault-injection side channels are out of scope.
