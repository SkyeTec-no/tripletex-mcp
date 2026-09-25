import { test } from "node:test";
import assert from "node:assert/strict";
import { TripletexClient } from "./tripletex-client.js";
import { transformVoucherPosting } from "./tripletex-transform.js";

// create_opening_balance registers on the PROCESS env but must refuse on the CLIENT's
// resolved target: on the header-auth HTTP path, x-tripletex-env overrides the process
// env per request. These pin the resolution the handler's guard relies on.
test("a per-credential env overrides the process env when resolving the target", () => {
  const saved = process.env.TRIPLETEX_ENV;
  process.env.TRIPLETEX_ENV = "test";
  try {
    assert.equal(new TripletexClient({ jwt: "x" }).targetsTestEnvironment(), true);
    assert.equal(new TripletexClient({ jwt: "x", env: "production" }).targetsTestEnvironment(), false);
  } finally {
    if (saved === undefined) delete process.env.TRIPLETEX_ENV;
    else process.env.TRIPLETEX_ENV = saved;
  }
});

test("no env anywhere resolves to tripletex.no", () => {
  const saved = process.env.TRIPLETEX_ENV;
  delete process.env.TRIPLETEX_ENV;
  try {
    assert.equal(new TripletexClient({ jwt: "x" }).targetsTestEnvironment(), false);
  } finally {
    if (saved !== undefined) process.env.TRIPLETEX_ENV = saved;
  }
});

test("a NOK posting without amountGrossCurrency gets it defaulted to amountGross", () => {
  const out = transformVoucherPosting({ accountId: 1, amountGross: 150, date: "2026-03-01" });
  assert.equal(out.amountGrossCurrency, 150);
  const fx = transformVoucherPosting({ accountId: 1, amountGross: 150, amountGrossCurrency: 13, date: "2026-03-01" });
  assert.equal(fx.amountGrossCurrency, 13);
});
