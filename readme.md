# Wahn

**Policy Based Access Control**

## Evalutation Process

1. Outcome defaults to: `deny`.
2. Find all applicable policies.
   a. If none found: `outcome=deny`
3. Evaluate all applicable polices.
4. Is there an explict `deny` for the `resource`?
   a. If`yes`then`outcome=deny`and exit evaluation b. If`no` then continue.
5. Is there an `allow`?
   a. If `yes` then `outcome=allow` and exit evaluation
   b. If `no` then continue.
6. No `allow` found: `outcome=deny`
