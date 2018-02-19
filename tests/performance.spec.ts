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

import {
    timeExecution,
    TimeExecutionOptions,
    Timings,
    TimedPerformance,
} from "wedgetail";

const numOfPoliciesToGenerate: number = 5000;
const numOfTimedFunctionCalls: number = 10000;
const maxExecutionTimeMs: number = 2;

const allowedPerformance: Timings = {
    high: 20,
    low: 1,
    average: 0.5,
    percentiles: {
        ninetyNinth: 1,
        ninetyFifth: 0.95,
        ninetieth: 0.9,
        tenth: 0.6,
    },
};

test("Performance of simple policy", async t => {
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

    const timings: TimedPerformance = await timeExecution({
        expectedTimings: allowedPerformance,
        numberOfExecutions: numOfTimedFunctionCalls,
        callback: () => {
            wahn.evaluateAccess({
                context,
                action,
                resource,
            });
        },
    });

    t.true(timings.results.passed, `Execution took too long.`);

    if (timings.results.passed === false) {
        console.log({ timings });
    }
});

test("Performance of many simple policy", async t => {
    const roles: string[] = [faker.name.jobTitle()];
    const context: RequestContext = {
        user: {
            id: faker.random.uuid(),
            roles: roles,
        },
    };

    function generatePolicy(): Policy {
        const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
        const action: string = faker.hacker.verb();
        return {
            id: faker.random.uuid(),
            resources: [resource],
            actions: [action],
            effect: PolicyEffect.Allow,
            roles: [faker.name.jobTitle(), faker.name.jobTitle()],
        };
    }

    const policies: Policy[] = Array(numOfPoliciesToGenerate).map(
        generatePolicy,
    );

    // Generate a sinle policy to append, that will work
    const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
    const action: string = faker.hacker.verb();
    const policy: Policy = {
        id: faker.random.uuid(),
        resources: [resource],
        actions: [action],
        effect: PolicyEffect.Allow,
        roles: roles,
    };

    policies.push(policy);

    const wahn: Wahn = new Wahn({
        policies,
    });

    const timings: TimedPerformance = await timeExecution({
        expectedTimings: allowedPerformance,
        numberOfExecutions: numOfTimedFunctionCalls,
        callback: () => {
            wahn.evaluateAccess({
                context,
                action,
                resource,
            });
        },
    });

    t.true(timings.results.passed, `Execution took too long.`);

    if (timings.results.passed === false) {
        console.log({ timings });
    }
});

test("Performance of multiple policies with multiple conditions on request object (ALLOW)", async t => {
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

    function generatePolicy(): Policy {
        const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
        const action: string = faker.hacker.verb();

        const condition: PolicyCondition = {
            field: "request.user.id",
            expectedOnContext: "user.id",
            operator: PolicyOperator.match,
        };
        const conditionTwo: PolicyCondition = {
            field: "request.user.ip",
            expectedOnContext: "user.knownIp",
            operator: PolicyOperator.match,
        };

        return {
            id: faker.random.uuid(),
            resources: [resource],
            actions: [action],
            effect: PolicyEffect.Allow,
            conditions: [condition, conditionTwo],
            roles: [faker.name.jobTitle(), faker.name.jobTitle()],
        };
    }
    const policies: Policy[] = Array(numOfPoliciesToGenerate).map(
        generatePolicy,
    );

    // Generate a sinle policy to append, that will work
    const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
    const action: string = faker.hacker.verb();

    const condition: PolicyCondition = {
        field: "request.user.id",
        expectedOnContext: "user.id",
        operator: PolicyOperator.match,
    };
    const conditionTwo: PolicyCondition = {
        field: "request.user.ip",
        expectedOnContext: "user.knownIp",
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
    policies.push(policy);

    // Create a new wahn
    const wahn: Wahn = new Wahn({
        policies,
    });

    const timings: TimedPerformance = await timeExecution({
        expectedTimings: allowedPerformance,
        numberOfExecutions: numOfTimedFunctionCalls,
        callback: () => {
            wahn.evaluateAccess({
                context,
                action,
                resource,
            });
        },
    });

    t.true(timings.results.passed, `Execution took too long.`);

    if (timings.results.passed === false) {
        console.log({ timings });
    }
});

/**
 * In this test, we run evaluateAccess 5000 times, and average the time result
 */
test("Performance of multiple policies with multiple conditions on request object (ALLOW)", async t => {
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

    function generatePolicy(): Policy {
        const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
        const action: string = faker.hacker.verb();

        const condition: PolicyCondition = {
            field: "request.user.id",
            expectedOnContext: "user.id",
            operator: PolicyOperator.match,
        };
        const conditionTwo: PolicyCondition = {
            field: "request.user.ip",
            expectedOnContext: "user.knownIp",
            operator: PolicyOperator.match,
        };

        return {
            id: faker.random.uuid(),
            resources: [resource],
            actions: [action],
            effect: PolicyEffect.Allow,
            conditions: [condition, conditionTwo],
            roles: [faker.name.jobTitle(), faker.name.jobTitle()],
        };
    }
    const policies: Policy[] = Array(numOfPoliciesToGenerate).map(
        generatePolicy,
    );

    // Generate a sinle policy to append, that will work
    const resource: string = `${faker.hacker.noun()}::${faker.hacker.noun()}`;
    const action: string = faker.hacker.verb();

    const condition: PolicyCondition = {
        field: "request.user.id",
        expectedOnContext: "user.id",
        operator: PolicyOperator.match,
    };
    const conditionTwo: PolicyCondition = {
        field: "request.user.ip",
        expectedOnContext: "user.knownIp",
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
    policies.push(policy);

    // Create a new wahn
    const wahn: Wahn = new Wahn({
        policies,
    });

    const timings: TimedPerformance = await timeExecution({
        expectedTimings: allowedPerformance,
        numberOfExecutions: numOfTimedFunctionCalls,
        callback: () => {
            wahn.evaluateAccess({
                context,
                action,
                resource,
            });
        },
    });

    t.true(timings.results.passed, `Execution took too long.`);

    if (timings.results.passed === false) {
        console.log({ timings });
    }
});
