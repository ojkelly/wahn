import * as mm from "micromatch";
import * as debug from "debug";
import {
    Wahn,
    WahnEvaluationOptions,
    Policy,
    PolicyEffect,
    PolicyOperator,
    PolicyCondition,
    RequestContext,
} from "./index";

import { AuthorizationError, EvaluationDeniedError } from "./errors";

const info: debug.IDebugger = debug("wahn:info");
const log: debug.IDebugger = debug("wahn:log");
const warn: debug.IDebugger = debug("wahn:warn");

/**
 * Get a value by key on an object by a 'dot.seperated.path.to.the.key'
 */
function get<obj>(obj: obj, path): any {
    return path.split(".").reduce((obj = {}, key) => obj[key], obj);
}

function reduceToBoolean(accumulator: boolean, currentOutcome: boolean) {
    // Any true value, makes this condition true
    if (accumulator === true) {
        return true;
    } else {
        return currentOutcome;
    }
}
/**
 * Make a decision about access for a request
 *
 * @param options
 */
function evaluateAccess({
    policies,
    context,
    action,
    resource,
}: WahnInternalEvaluationOptions): boolean {
    try {
        // 1. Outcome defaults to: `deny`.
        let outcome: boolean = false;

        // Check if any of the policies have the action
        const matchedPolicies: Policy[] = matchPolicies({
            policies,
            action,
            resource,
            context,
        });
        // 3. Evaluate all applicable polices.

        // a. If no policies are found: `outcome=deny`
        if (
            typeof matchedPolicies.length === "undefined" ||
            matchedPolicies.length === 0
        ) {
            throw new EvaluationDeniedError(
                "",
                "No policies matched the request.",
            );
        }
        debug(
            `Matched policies for: ${JSON.stringify({
                resource,
                action,
                context,
                matchedPolicies,
            })}`,
        );
        matchedPolicies.forEach((policy: Policy) => {
            // 4. Is there an explict `deny` for the `action`
            if (policy.effect === PolicyEffect.Deny) {
                // a. If`yes`then`outcome=deny`and exit evaluation b. If`no` then continue.
                throw new EvaluationDeniedError(
                    policy.id,
                    "Access has been explicty denied.",
                );
            }

            // 5. Is there an `allow`?
            if (policy.effect === PolicyEffect.Allow) {
                // a. If `yes` then `outcome=allow` and exit evaluation
                outcome = true;
            } else {
                throw new EvaluationDeniedError(
                    policy.id,
                    "Access has not been allowed.",
                );
            }
        });
        // b. If `no` then continue.

        // 6. No `allow` found: `outcome=deny`
        return outcome;
    } catch (err) {
        if (err instanceof EvaluationDeniedError || AuthorizationError) {
        } else {
            console.log(err.message, err.stack);
        }
        throw err;
    }
}

/**
 * Match the policies to this request.
 *
 * Basically, we need to evaluate the policies and their conditions
 * in order to see if the policy is applicable.
 *
 * Returns every policy that is applicable.
 * @param options
 */
function matchPolicies({
    policies,
    action,
    resource,
    context,
}: {
    policies: Policy[];
    action: string;
    resource: string;
    context: RequestContext;
}): Policy[] {
    try {
        return policies.filter((policy: Policy) => {
            let policyResourceCheck: boolean = false;
            let policyActionCheck: boolean = false;
            let policyConditionCheck: boolean = false;

            // Does the policy match the current action?
            if (mm.some(resource, policy.resources)) {
                log("Policy does match resource.");
                policyResourceCheck = true;
            } else {
                log("Policy does not match resource.");
                return false;
            }
            if (mm.some(action, policy.actions)) {
                log("Policy does match action.");
                policyActionCheck = true;
            } else {
                log("Policy does not match action.");
                return false;
            }

            // Does the policy have a condition?
            if (
                typeof policy.conditions !== "undefined" &&
                policy.conditions.length >= 1
            ) {
                // If this policy has condtions we need to check the conditions
                policyConditionCheck = evaluateAllConditions({
                    policy,
                    resource,
                    context,
                });
            } else {
                // If the policy has no conditions, then it matches
                policyConditionCheck = true;
            }
            debug(
                JSON.stringify({
                    policy,
                    policyResourceCheck,
                    policyActionCheck,
                    policyConditionCheck,
                }),
            );
            // If all checks passed this policy is has matched
            if (
                policyResourceCheck &&
                policyActionCheck &&
                policyConditionCheck
            ) {
                return true;
            }
            return false;
        });
    } catch (err) {
        throw err;
    }
}

/**
 * Evaluate all conditions on a policy
 *
 * @param options
 */
function evaluateAllConditions({
    policy,
    resource,
    context,
}: {
    policy: Policy;
    resource: string;
    context: RequestContext;
}): boolean {
    try {
        let outcome: boolean = false;
        if (typeof policy.conditions === "undefined") {
            throw new EvaluationDeniedError(
                policy.id,
                "Access has not been allowed.",
            );
        }
        // Do the condtions make this policy applicable?
        // All conditions must return true, else outcome in DENY
        outcome = policy.conditions
            .map((condition: PolicyCondition) => {
                return evaluateCondition({ condition, resource, context });
            })
            .reduce((accumulator: boolean, currentOutcome: boolean) => {
                // All values must be true for this condition to evaluate true
                // therefore, we can simply add the currentOutcome to the accumulator
                // and stop, if the accumulator becomes false.
                if (accumulator === false) {
                    return false;
                } else {
                    return currentOutcome;
                }
            });
        return outcome;
    } catch (err) {
        throw err;
    }
}

/**
 * Evaluate a single condition
 *
 * If there are multiple expected values, then they are evaluated as
 * OR, only 1 of them needs to be true for the condition outcome to
 * be true
 *
 * @param options
 */
function evaluateCondition({
    condition,
    resource,
    context,
}: {
    condition: PolicyCondition;
    resource: string;
    context: RequestContext;
}): boolean {
    try {
        let outcome: boolean = false;

        if (
            typeof condition.expected !== "undefined" &&
            Array.isArray(condition.expected)
        ) {
            outcome = condition.expected
                .map(() =>
                    matchSingleValue({
                        condition,
                        resource,
                        context,
                        expected: true,
                        expectedOnContext: false,
                    }),
                )
                .reduce(reduceToBoolean);
        } else if (
            typeof condition.expectedOnContext !== "undefined" &&
            Array.isArray(condition.expectedOnContext)
        ) {
            outcome = condition.expectedOnContext
                .map(() =>
                    matchSingleValue({
                        condition,
                        resource,
                        context,
                        expected: false,
                        expectedOnContext: true,
                    }),
                )
                .reduce(reduceToBoolean);
        }
        return outcome;
    } catch (err) {
        throw err;
    }
}

/**
 * Match a single value for a condition
 * @param options
 */
function matchSingleValue({
    condition,
    resource,
    context,
    expected,
    expectedOnContext,
}: {
    condition: PolicyCondition;
    resource: string;
    context: RequestContext;
    expected: boolean;
    expectedOnContext: boolean;
}): any {
    try {
        // Always default to false
        let outcome: boolean = false;
        // Defensively setup some variables
        let matchResult: boolean | undefined = undefined;
        let numericResult:
            | PolicyOperator.lessThan
            | PolicyOperator.greaterThan
            | undefined = undefined;

        // First process the comparison
        if (
            // String Conditions
            condition.operator === PolicyOperator.match ||
            condition.operator === PolicyOperator.notMatch
        ) {
            if (expected === true && Array.isArray(condition.expected)) {
                matchResult = condition.expected
                    .map((val: string | number) =>
                        mm.isMatch(get(context, condition.field), `${val}`),
                    )
                    .reduce(reduceToBoolean);
            } else if (
                expectedOnContext === true &&
                Array.isArray(condition.expectedOnContext)
            ) {
                matchResult = condition.expectedOnContext
                    .map((val: string) =>
                        mm.any(
                            get(context, condition.field),
                            get(context, val),
                        ),
                    )
                    .reduce(reduceToBoolean);
            } else {
                // Invalid condition, skip it
                log("Invalid condition, skip it");
            }
        } else if (
            // Numeric conditions
            condition.operator === PolicyOperator.lessThan ||
            condition.operator === PolicyOperator.greaterThan
        ) {
            const field: number = get(context, condition.field);
            let expectedValue: number | undefined = undefined;

            if (expected === true) {
                expectedValue = Number(condition.expected);
            } else if (expectedOnContext === true) {
                expectedValue = get(context, condition.expectedOnContext);
            } else {
                // Invalid condition, skip it
                log("Invalid condition, skip it");
            }
            if (field > Number(condition.expected)) {
                numericResult = PolicyOperator.greaterThan;
            } else if (field < Number(condition.expected)) {
                numericResult = PolicyOperator.lessThan;
            }
        }

        // Now check if the comparision matches to what we were expecting
        switch (condition.operator) {
            case PolicyOperator.match:
                if (matchResult === true) {
                    outcome = true;
                }
                break;
            case PolicyOperator.notMatch:
                if (matchResult === false) {
                    outcome = true;
                }
                break;
            case PolicyOperator.lessThan:
                if (numericResult === PolicyOperator.lessThan) {
                    outcome = true;
                }
            case PolicyOperator.greaterThan:
                if (numericResult === PolicyOperator.greaterThan) {
                    outcome = true;
                }
        }
        return outcome;
    } catch (err) {
        throw err;
    }
}

type WahnInternalEvaluationOptions = {
    policies: Policy[];
    context: RequestContext;
    action: string;
    resource: string;
};

export {
    WahnInternalEvaluationOptions,
    // Fuctions
    evaluateAccess,
    evaluateAllConditions,
    matchPolicies,
};
