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

// // [ Policy With Conditions ]-----------------------------------------------------------------------

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
        expected: allowedIp,
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

test.skip("Evaluate a policy with condition of IP on request where IP is stored on Policy (DENY)", async t => {
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
        field: "${request.ip}",
        expected: allowedIp,
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

    t.false(
        wahn.evaluateAccess({
            context,
            action,
            resource: faker.random.uuid(),
        }),
        "Failed to prevent access",
    );
});

// test.skip("evaluate conditional policy", async t => {
//     const conditionalRoles: string[] = ["user", "conditional user"];
//     const testCondition: string = "someValue";
//     const conditionalContext: RequestContext = {
//         user: {
//             id: "conditionalUserId",
//             roles: conditionalRoles,
//             ip: "127.0.0.1",
//         },
//         testCondition,
//     };

//     const conditionalAction: string = "test::action:conditional";

//     const conditionalPolicy: Policy = {
//         id: "conditionalPolicy",
//         actions: [conditionalAction],
//         effect: PolicyEffect.Allow,
//         roles: conditionalRoles,
//         conditions: [
//             {
//                 field: "testCondition",
//                 operator: PolicyOperator.match,
//                 expected: testCondition,
//                 object: PolicyConditionObject.Context,
//             },
//         ],
//     };
//     let logCallbackResult: LoggingCallbackLog | undefined = undefined;
//     const loggingCallback: LoggingCallback = (
//         log: LoggingCallbackLog,
//     ): void => {
//         logCallbackResult = log;
//     };

//     const wahn: Wahn = new Wahn({
//         policies: [conditionalPolicy],
//         loggingCallback,
//     });

//     t.deepEqual(wahn.getPolicies(), [conditionalPolicy]);

//     t.true(
//         wahn.evaluateAccess({
//             context: conditionalContext,
//             action: conditionalAction,
//         }),
//     );
//     const failureAction: string = "Action::TheUserCannotAccess";
//     t.false(
//         wahn.evaluateAccess({
//             context: conditionalContext,
//             action: failureAction,
//         }),
//     );

//     t.deepEqual(
//         logCallbackResult,
//         {
//             policyId: "",
//             context: conditionalContext,
//             action: failureAction,
//             reason: "No policies matched the request.",
//         },
//         "LoggingCallbackResult is wrong",
//     );
// });

// // [ Policy With resource Condition ]---------------------------------------------------------------
// test.skip("Evaluate Policy With resource Condition", async t => {
//     const conditionalroles: string[] = ["user", "conditional user"];
//     const conditionalContext: RequestContext = {
//         user: {
//             id: "conditionalUserId",
//             roles: conditionalroles,
//         },
//         request: {
//             ip: "127.0.0.1",
//         },
//     };

//     const conditionalresource: string = "test::resource:conditional";

//     const conditionalPolicy: Policy = {
//         id: "conditionalPolicy",
//         resources: [resource, conditionalresource],
//         effect: PolicyEffect.Allow,
//         roles: conditionalroles,
//         conditions: [
//             {
//                 field: "user.id",
//                 operator: PolicyOperator.match,
//                 expected: "user.id",
//                 object: PolicyConditionObject.resource,
//             },
//         ],
//     };
//     let logCallbackResult: LoggingCallbackLog | undefined = undefined;
//     const loggingCallback: LoggingCallback = (
//         log: LoggingCallbackLog,
//     ): void => {
//         logCallbackResult = log;
//     };

//     const wahn: Wahn = new Wahn({
//         policies: [conditionalPolicy],
//         loggingCallback,
//     });

//     t.deepEqual(wahn.getPolicies(), [conditionalPolicy]);

//     t.true(
//         wahn.evaluateAccess({
//             context: conditionalContext,
//             resource: conditionalresource,
//             resourceObject: {
//                 user: {
//                     id: "conditionalUserId",
//                 },
//             },
//         }),
//     );
//     const failureresource: string = "AresourceTheUserCannotAccess";
//     t.false(
//         wahn.evaluateAccess({
//             context: conditionalContext,
//             resource: failureresource,
//         }),
//     );

//     t.deepEqual(
//         logCallbackResult,
//         {
//             context: conditionalContext,
//             resource: failureresource,
//             reason: "No policies matched the request.",
//         },
//         "LoggingCallbackResult is wrong",
//     );
// });
