## Race Conditions / TOCTOU
Where: any check-then-act on shared state — balance/withdraw/transfer, coupon/gift-card/voucher redeem, refund, vote/like, invite/referral bonus, "claim once" rewards, file upload+scan, OTP/2FA attempt counters, account creation on unique fields.
Exploit: fire N identical requests CONCURRENTLY (not sequentially) so several pass the check before any commits. Same session/token reused.
Tooling: Burp Turbo Intruder / Repeater "send group in parallel"; `curl` backgrounded (`for i in $(seq 20); do curl ... & done; wait`); HTTP/2 single-packet attack (all requests in one TCP packet -> near-zero jitter, defeats most locks). Python `asyncio`+`aiohttp` gather.
Signals of a win: balance goes negative / double-credited; one coupon applied many times; limit-1 resource acquired twice; 2FA lockout bypassed by parallel guesses.
Limit-overrun class: single-request races (limit-1 purchased 5x), multi-endpoint (state stored in step 1 read in step 2), and "rate-limit" bypass via parallelism.
Escalate: financial loss (double-spend), auth bypass (parallel OTP), privilege/quota abuse. Report the exact concurrency and observed inconsistent state.
