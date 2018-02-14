import test from "ava";
import { Wahn, Policy, PolicyAction, PolicyContext } from "./index";

// [ Simple Policy ]--------------------------------------------------------------------------------
const simpleRoles: string[] = ["user", "simple user"];
const context: PolicyContext = {
    user: {
        id: "simpleUserId",
        roles: simpleRoles,
    },
};

const simpleResource: string = "test::resource";

const simplePolicy: Policy = {
    resources: [simpleResource],
    action: PolicyAction.Allow,
    roles: simpleRoles,
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

    t.true(wahn.evaluateAccess({ context, resource: simpleResource }));
});

// [ Policy With Context ]--------------------------------------------------------------------------

// [ Policy With User ]-----------------------------------------------------------------------------
