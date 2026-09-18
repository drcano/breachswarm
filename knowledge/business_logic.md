## Business Logic Flaws
Where: checkout/payment, cart, coupons/gift-cards, refunds, loyalty points, quotas,
multi-step workflows (KYC, onboarding, approval), quantity/price fields, currency.
Money manipulation:
- Negative / zero / fractional quantity or price -> negative total credits your balance;
  `qty=-1`, `price=0`, `amount=0.001`, integer overflow (`qty=2147483648`).
- Currency confusion: pay in a weaker currency, or omit/override the currency field.
- Client-trusted price: the client sends the price/total; tamper it. Server must recompute.
- Rounding: many tiny transactions exploit round-down; discount stacking.
Coupon/voucher/refund abuse: reuse a single-use coupon (also see race_condition for
parallel redeem), apply multiple codes, refund more than paid, refund to a different
account, cancel-after-ship.
Workflow / state bypass: skip a step (go straight to the "confirmed"/"paid" endpoint),
replay a step, do steps out of order, reuse a one-time token, downgrade a completed order
back to editable, approve your own request.
Quota/limit bypass: per-account limits reset by re-registration; free-trial abuse;
"limit 1" beaten by parallelism (race) or by a second endpoint.
Identity/authorization logic: act on behalf of another via a tenant/org id you supply;
role implied by a field the client controls.
Confirm impact concretely (balance changed, item obtained free, step skipped) — logic
bugs need a clear before/after, not just an odd response. High business impact, often
out of scanner reach = high bounty.
