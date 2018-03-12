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
    AuthorizationDeniedError,
} from "../src/index";

// [ Policy With Conditions ]-----------------------------------------------------------------------

test("Evaluate a policy with condition of IP on request where IP is stored on Policy (ALLOW)", async t => {
    // Setup some initial values for this policy
    const allowedIp: string = faker.internet.ip();
    const roles: string[] = [faker.name.jobTitle(), faker.name.jobTitle()];
    const context: RequestContext = {
        user: {
            id: faker.random.uuid(),
            roles: roles,
        },
        request: {
            ip: allowedIp,
        },
    };
    const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
    const action: string = faker.hacker.verb();

    const condition: PolicyCondition = {
        field: "request.ip",
        expected: [allowedIp],
        operator: PolicyOperator.match,
    };

    // Assemble our policy
    const policy: Policy = {
        id: faker.random.uuid(),
        resources: [resource],
        actions: [action],
        effect: PolicyEffect.Allow,
        conditions: [condition],
        roles: roles,
    };

    // Add in our logging callback
    let logCallbackResult: LoggingCallbackLog | undefined = undefined;
    const loggingCallback: LoggingCallback = (
        log: LoggingCallbackLog,
    ): void => {
        logCallbackResult = log;
    };

    // Create a new wahn
    const wahn: Wahn = new Wahn({
        policies: [policy],
        loggingCallback,
    });

    t.true(
        wahn.evaluateAccess({ context, resource, action }),
        "Failed to give access",
    );
});

test(
    "Evaluate a policy with condition of IP on request where IP is stored on Policy (DENY)" +
        " with log calback",
    async t => {
        // Setup some initial values for this policy
        const allowedIp: string = faker.internet.ip();
        const roles: string[] = [faker.name.jobTitle(), faker.name.jobTitle()];
        const context: RequestContext = {
            user: {
                id: faker.random.uuid(),
                roles: roles,
            },
            request: {
                ip: allowedIp,
            },
        };
        const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;

        const action: string = faker.hacker.verb();

        const condition: PolicyCondition = {
            field: "request.ip",
            expected: [allowedIp],
            operator: PolicyOperator.match,
        };

        const policyId: string = faker.random.uuid();

        // Assemble our policy
        const policy: Policy = {
            id: policyId,
            resources: [resource],
            actions: [action],
            effect: PolicyEffect.Allow,
            conditions: [condition],
            roles: roles,
        };

        // Add in our logging callback
        let logCallbackResult: LoggingCallbackLog | undefined = undefined;
        const loggingCallback: LoggingCallback = (
            log: LoggingCallbackLog,
        ): void => {
            logCallbackResult = log;
        };

        // Create a new wahn
        const wahn: Wahn = new Wahn({
            policies: [policy],
            loggingCallback,
        });

        const failedResource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
        t.throws(
            () =>
                wahn.evaluateAccess({
                    context,
                    resource: failedResource,
                    action,
                }),
            AuthorizationDeniedError,
        );

        t.deepEqual(
            logCallbackResult,
            {
                policy: null,
                context,
                action,
                resource: failedResource,
                reason: "No policies matched the request.",
            },
            "LoggingCallbackResult is wrong",
        );
    },
);

test("Evaluate a policy with condition of user id must match user id on request object (ALLOW)", async t => {
    // Setup some initial values for this policy
    const roles: string[] = [faker.name.jobTitle(), faker.name.jobTitle()];
    const userId: string = faker.random.uuid();
    const context: RequestContext = {
        user: {
            id: userId,
            roles: roles,
        },
        request: {
            user: {
                id: userId,
            },
        },
    };
    const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
    const action: string = faker.hacker.verb();

    const condition: PolicyCondition = {
        field: "request.user.id",
        expectedOnContext: ["user.id"],
        operator: PolicyOperator.match,
    };
    // Assemble our policy
    const policy: Policy = {
        id: faker.random.uuid(),
        resources: [resource],
        actions: [action],
        effect: PolicyEffect.Allow,
        conditions: [condition],
        roles: roles,
    };

    // Create a new wahn
    const wahn: Wahn = new Wahn({
        policies: [policy],
    });

    t.true(
        wahn.evaluateAccess({ context, resource, action }),
        "Failed to give access",
    );
});

test("Evaluate a policy with multiple conditions on request object (ALLOW)", async t => {
    // Setup some initial values for this policy
    const allowedIp: string = faker.internet.ip();

    const roles: string[] = [faker.name.jobTitle(), faker.name.jobTitle()];
    const userId: string = faker.random.uuid();
    const context: RequestContext = {
        user: {
            id: userId,
            roles: roles,
            knownIp: allowedIp,
        },
        request: {
            user: {
                id: userId,
                ip: allowedIp,
            },
        },
    };
    const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
    const action: string = faker.hacker.verb();

    const condition: PolicyCondition = {
        field: "request.user.id",
        expectedOnContext: ["user.id"],
        operator: PolicyOperator.match,
    };
    const conditionTwo: PolicyCondition = {
        field: "request.user.ip",
        expectedOnContext: ["user.knownIp"],
        operator: PolicyOperator.match,
    };
    // Assemble our policy
    const policy: Policy = {
        id: faker.random.uuid(),
        resources: [resource],
        actions: [action],
        effect: PolicyEffect.Allow,
        conditions: [condition, conditionTwo],
        roles: roles,
    };

    // Create a new wahn
    const wahn: Wahn = new Wahn({
        policies: [policy],
    });

    t.true(
        wahn.evaluateAccess({ context, resource, action }),
        "Failed to give access",
    );
});

test("Evaluate a policy with multiple conditions on request object (DENY) fail on resource", async t => {
    // Setup some initial values for this policy
    const allowedIp: string = faker.internet.ip();

    const roles: string[] = [faker.name.jobTitle(), faker.name.jobTitle()];
    const userId: string = faker.random.uuid();
    const context: RequestContext = {
        user: {
            id: userId,
            roles: roles,
            knownIp: allowedIp,
        },
        request: {
            user: {
                id: userId,
                ip: allowedIp,
            },
        },
    };
    const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
    const action: string = faker.hacker.verb();

    const condition: PolicyCondition = {
        field: "request.user.id",
        expectedOnContext: ["user.id"],
        operator: PolicyOperator.match,
    };
    const conditionTwo: PolicyCondition = {
        field: "request.user.ip",
        expectedOnContext: ["user.knownIp"],
        operator: PolicyOperator.match,
    };
    // Assemble our policy
    const policy: Policy = {
        id: faker.random.uuid(),
        resources: [resource],
        actions: [action],
        effect: PolicyEffect.Allow,
        conditions: [condition, conditionTwo],
        roles: roles,
    };

    // Add in our logging callback
    let logCallbackResult: LoggingCallbackLog | undefined = undefined;
    const loggingCallback: LoggingCallback = (
        log: LoggingCallbackLog,
    ): void => {
        logCallbackResult = log;
    };

    // Create a new wahn
    const wahn: Wahn = new Wahn({
        policies: [policy],
        loggingCallback,
    });

    const failedResource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;

    t.throws(
        () =>
            wahn.evaluateAccess({
                context,
                resource: failedResource,
                action,
            }),
        AuthorizationDeniedError,
    );

    t.deepEqual(
        logCallbackResult,
        {
            policy: null,
            context,
            action,
            resource: failedResource,
            reason: "No policies matched the request.",
        },
        "LoggingCallbackResult is wrong",
    );
});

test("Evaluate a policy with multiple conditions on request object (DENY) fail on condition", async t => {
    // Setup some initial values for this policy

    const roles: string[] = [faker.name.jobTitle(), faker.name.jobTitle()];
    const userId: string = faker.random.uuid();
    const context: RequestContext = {
        user: {
            id: userId,
            roles: roles,
            knownIp: faker.internet.ip(),
        },
        request: {
            user: {
                id: userId,
                ip: faker.internet.ip(),
            },
        },
    };
    const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
    const action: string = faker.hacker.verb();

    const condition: PolicyCondition = {
        field: "request.user.id",
        expectedOnContext: ["user.id"],
        operator: PolicyOperator.match,
    };
    const conditionTwo: PolicyCondition = {
        field: "request.user.ip",
        expectedOnContext: ["user.knownIp"],
        operator: PolicyOperator.match,
    };
    // Assemble our policy
    const policy: Policy = {
        id: faker.random.uuid(),
        resources: [resource],
        actions: [action],
        effect: PolicyEffect.Allow,
        conditions: [condition, conditionTwo],
        roles: roles,
    };

    // Add in our logging callback
    let logCallbackResult: LoggingCallbackLog | undefined = undefined;
    const loggingCallback: LoggingCallback = (
        log: LoggingCallbackLog,
    ): void => {
        logCallbackResult = log;
    };

    // Create a new wahn
    const wahn: Wahn = new Wahn({
        policies: [policy],
        loggingCallback,
    });

    t.throws(
        () =>
            wahn.evaluateAccess({
                context,
                resource,
                action,
            }),
        AuthorizationDeniedError,
    );

    t.deepEqual(
        logCallbackResult,
        {
            policy: null,
            context,
            action,
            resource,
            reason: "No policies matched the request.",
        },
        "LoggingCallbackResult is wrong",
    );
});

test("Evaluate a policy with numeric condition greater than stored on Policy (ALLOW)", async t => {
    // Setup some initial values for this policy
    const roles: string[] = [faker.name.jobTitle(), faker.name.jobTitle()];
    const context: RequestContext = {
        user: {
            id: faker.random.uuid(),
            roles: roles,
            // For example this session is 1200 seconds long
            sessionAge: 1200,
        },
    };
    const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
    const action: string = faker.hacker.verb();

    // If the session is less than 600 seconds old, then allow otherwise deny with MFARequired
    const condition: PolicyCondition = {
        field: "user.sessionAge",
        operator: PolicyOperator.greaterThan,
        expected: [600],
    };
    const denyType: string = "mfa-required";
    // Assemble our policy
    const policy: Policy = {
        id: faker.random.uuid(),
        resources: [resource],
        actions: [action],
        effect: PolicyEffect.Deny,
        denyType,
        conditions: [condition],
        roles: roles,
    };

    // Add in our logging callback
    let logCallbackResult: LoggingCallbackLog | undefined = undefined;
    const loggingCallback: LoggingCallback = (
        log: LoggingCallbackLog,
    ): void => {
        logCallbackResult = log;
    };

    // Create a new wahn
    const wahn: Wahn = new Wahn({
        policies: [policy],
        loggingCallback,
    });

    t.throws(
        () => wahn.evaluateAccess({ context, resource, action }),
        AuthorizationDeniedError,
    );
    try {
        wahn.evaluateAccess({ context, resource, action });
    } catch (AuthorizationDeniedError) {
        t.is(AuthorizationDeniedError.denyType, denyType);
    }
});
