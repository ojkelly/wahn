import test from "ava";
import { Wahn, Policy, PolicyAction } from "./index";

// [ Simple Policy ]--------------------------------------------------------------------------------
const simplePolicy: Policy = {
    resources: ["test::resource"],
    action: PolicyAction.Allow,
};

test("can create wahn class", async t => {
    const wahn: Wahn = new Wahn({
        policies: [simplePolicy],
    });

    // Check the instance is correct
    t.true(wahn instanceof Wahn);

    // Check we have policies
    t.deepEqual(wahn.getPolicies(), [simplePolicy]);
});

test("evaluate simple policy", async t => {
    const wahn: Wahn = new Wahn({
        policies: [simplePolicy],
    });
});

// [ Policy With Context ]--------------------------------------------------------------------------

// [ Policy With User ]-----------------------------------------------------------------------------
