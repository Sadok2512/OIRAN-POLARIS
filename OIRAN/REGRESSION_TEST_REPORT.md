# Regression Test Report

Executed after deployment on 2026-10-25.

| Suite | Result |
|---|---|
| Rust workspace | 119 passed, 0 failed |
| API crate | 16 passed, 0 failed |
| Capture helper crate | 12 passed, 0 failed |
| Live probe crate | 9 passed, 0 failed |
| Frontend TypeScript | PASS |
| Frontend unit tests | 9 passed, 0 failed |
| Frontend production build | PASS |
| Local Web health | HTTP 200 |
| Public gateway Web health | HTTP 200 |

The Rust suite covers IPC authorization, unauthorized peer rejection, allowlisting, lifecycle transitions, initialization failures, signal reporting, disk quota, stop ownership, PCAP integrity, historical datasets, session reconstruction, and Call Flow behavior.

Historical checksums remained unchanged:

- N2: `2f23390dd619dda464ec8f2cfbd3b9fe59ca0587b043f6267a8ffc5a752cf54e`
- N3: `806a4ae1eb758a1b2c08ae10d7b7f54881c5e571c7f80ed047f564cb222cb35a`
- N4: `8fad2f3401e79ea1695aa26cba649c03711e24ee0602625ec569ef82c3e6cfe7`
- Call Flow JSON: `bc89ddd79d23af2ad53a5bc0b46e69c988fbc02d69b92c9462ece760b27432cb`
- Call Flow HTML: `024d34492e713666d4ec318575fdb30f44d3c937b960d75c117bb22057c8a8f5`
