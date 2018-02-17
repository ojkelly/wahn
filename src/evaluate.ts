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

/** */
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
        throw new EvaluationDeniedError("", "No policies matched the request.");
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
function matchPolicies({ policies, action, resource, context }): Policy[] {
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
            policyConditionCheck = evaluateConditions({
                policy,
                resource,
                context,
            });
        } else {
            // If the policy has no conditions, then it matches
            policyConditionCheck = true;
        }

        // If all checks passed this policy is has matched
        if (policyResourceCheck && policyActionCheck && policyConditionCheck) {
            return true;
        }
        return false;
    });
}

function evaluateConditions({ policy, resource, context }): boolean {
    console.log("evaluateConditions", {
        policy,
        conditions: policy.conditions,
        resource,
        context,
    });
    let outcome: boolean = false;
    // Do the condtions make this policy applicable?
    // All conditions must return true, else outcome in DENY
    policy.conditions.map((condition: PolicyCondition) => {
        switch (condition.operator) {
            case PolicyOperator.match:
                console.log({
                    condition,
                    context,
                    fieldPath: condition.field,
                    field: context[condition.field],
                    t: get(context, condition.field),
                });
                if (
                    mm.isMatch(
                        get(context, condition.field),
                        `${condition.expected}`,
                    )
                ) {
                    outcome = true;
                }
                break;
            case PolicyOperator.notMatch:
                if (
                    mm.isMatch(
                        get(context, condition.field),
                        `${condition.expected}`,
                    ) === false
                ) {
                    outcome = true;
                }
                break;
        }
    });
    return outcome;
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
    evaluateConditions,
    matchPolicies,
};
