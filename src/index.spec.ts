import test from "ava";
import {
    Wahn,
    Policy,
    PolicyAction,
    RequestContext,
    PolicyOperator,
} from "./index";

// [ Simple Policy ]--------------------------------------------------------------------------------
const simpleRoles: string[] = ["user", "simple user"];
const context: RequestContext = {
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
    t.false(
        wahn.evaluateAccess({
            context,
            resource: "AResourceTheUserCannotAccess",
        }),
    );
});

// [ Policy With Conditions ]-----------------------------------------------------------------------
test("evaluate conditional policy", async t => {
    const conditionalRoles: string[] = ["user", "conditional user"];
    const testCondition: string = "someValue";
    const conditionalContext: RequestContext = {
        user: {
            id: "conditionalUserId",
            roles: conditionalRoles,
            ip: "127.0.0.1",
        },
        testCondition,
    };

    const conditionalResource: string = "test::resource:conditional";

    const conditionalPolicy: Policy = {
        resources: [simpleResource, conditionalResource],
        action: PolicyAction.Allow,
        roles: conditionalRoles,
        conditions: [
            {
                field: "testCondition",
                operator: PolicyOperator.match,
                value: testCondition,
            },
        ],
    };

    const wahn: Wahn = new Wahn({
        policies: [conditionalPolicy],
    });

    t.deepEqual(wahn.getPolicies(), [conditionalPolicy]);

    t.true(
        wahn.evaluateAccess({
            context: conditionalContext,
            resource: conditionalResource,
        }),
    );
    t.false(
        wahn.evaluateAccess({
            context: conditionalContext,
            resource: "AResourceTheUserCannotAccess",
        }),
    );
});

// [ Policy With User ]-----------------------------------------------------------------------------
