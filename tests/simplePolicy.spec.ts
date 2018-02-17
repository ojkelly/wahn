import test from "ava";
import * as faker from "faker";
import {
    Wahn,
    Policy,
    PolicyEffect,
    RequestContext,
    PolicyCondition,
    PolicyOperator,
    LoggingCallback,
    LoggingCallbackLog,
} from "../src/index";

// [ Simple Policy ]--------------------------------------------------------------------------------

test("Can create wahn class and add policys", async t => {
    const roles: string[] = [faker.name.jobTitle()];
    const context: RequestContext = {
        user: {
            id: faker.random.uuid(),
            roles: roles,
        },
    };

    const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
    const action: string = faker.hacker.verb();

    const policy: Policy = {
        id: faker.random.uuid(),
        resources: [resource],
        actions: [action],
        effect: PolicyEffect.Allow,
        roles: roles,
    };

    const wahn: Wahn = new Wahn({
        policies: [policy],
    });

    // Check the instance is correct
    t.true(wahn instanceof Wahn);

    // Check we have policies
    t.deepEqual(wahn.getPolicies(), [policy]);
});

test("Evaluate request which should be allowed", async t => {
    const roles: string[] = [faker.name.jobTitle()];
    const context: RequestContext = {
        user: {
            id: faker.random.uuid(),
            roles: roles,
        },
    };

    const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
    const action: string = faker.hacker.verb();

    const policy: Policy = {
        id: faker.random.uuid(),
        resources: [resource],
        actions: [action],
        effect: PolicyEffect.Allow,
        roles: roles,
    };

    const wahn: Wahn = new Wahn({
        policies: [policy],
    });

    t.true(
        wahn.evaluateAccess({ context, resource, action }),
        "Failed to give access",
    );
});

test("Evaluate request which should be denied", async t => {
    const roles: string[] = [faker.name.jobTitle()];
    const context: RequestContext = {
        user: {
            id: faker.random.uuid(),
            roles: roles,
        },
    };

    const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
    const action: string = faker.hacker.verb();

    const policy: Policy = {
        id: faker.random.uuid(),
        resources: [resource],
        actions: [action],
        effect: PolicyEffect.Allow,
        roles: roles,
    };

    const wahn: Wahn = new Wahn({
        policies: [policy],
    });

    t.false(
        wahn.evaluateAccess({
            context,
            action,
            resource: faker.random.uuid(),
        }),
        "Failed to prevent access",
    );
});
