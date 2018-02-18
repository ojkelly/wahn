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

        policies.forEach((policy: Policy) => {
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

        if (typeof condition.expected !== "undefined") {
            if (typeof condition.expected === "string") {
                outcome = matchSingleValue({
                    condition,
                    resource,
                    context,
                    matchExpected: true,
                    matchExpectedOnContext: false,
                });
            } else if (Array.isArray(condition.expected)) {
                outcome = condition.expected
                    .map((expected: string) =>
                        matchSingleValue({
                            condition,
                            resource,
                            context,
                            matchExpected: true,
                            matchExpectedOnContext: false,
                        }),
                    )
                    .reduce((accumulator: boolean, currentOutcome: boolean) => {
                        // Any true value, makes this condition true
                        if (accumulator === true) {
                            return true;
                        } else {
                            return currentOutcome;
                        }
                    });
            }
        } else if (typeof condition.expectedOnContext !== "undefined") {
            if (typeof condition.expectedOnContext === "undefined") {
            } else if (typeof condition.expectedOnContext === "string") {
                outcome = matchSingleValue({
                    condition,
                    resource,
                    context,
                    matchExpected: false,
                    matchExpectedOnContext: true,
                });
            } else if (Array.isArray(condition.expectedOnContext)) {
                outcome = condition.expectedOnContext
                    .map((expected: string) =>
                        matchSingleValue({
                            condition,
                            resource,
                            context,
                            matchExpected: false,
                            matchExpectedOnContext: true,
                        }),
                    )
                    .reduce((accumulator: boolean, currentOutcome: boolean) => {
                        // Any true value, makes this condition true
                        if (accumulator === true) {
                            return true;
                        } else {
                            return currentOutcome;
                        }
                    });
            }
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
    matchExpected,
    matchExpectedOnContext,
}: {
    condition: PolicyCondition;
    resource: string;
    context: RequestContext;
    matchExpected: boolean;
    matchExpectedOnContext: boolean;
}): boolean {
    try {
        let outcome: boolean = false;
        console.log("matchSingleValue", {
            condition,
            context,
            matchExpected,
            matchExpectedOnContext,
            resource,
            fieldPath: condition.field,
            field: get(context, condition.field),
        });
        let matchResult: boolean | undefined = undefined;

        if (matchExpected === true) {
            matchResult = mm.isMatch(
                get(context, condition.field),
                `${condition.expected}`,
            );
        } else if (matchExpectedOnContext === true) {
            matchResult = mm.isMatch(
                get(context, condition.field),
                get(context, condition.expectedOnContext),
            );
        } else {
            // Invalid condition, skip it
            log("Invalid condition, skip it");
        }

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
            case PolicyOperator.greaterThan:
                throw new Error("Condition greaterThan not implemented yet.");
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
