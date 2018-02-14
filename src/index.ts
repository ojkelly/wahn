import * as mm from "micromatch";
import * as debug from "debug";

const info: debug.IDebugger = debug("wahn:info");
const log: debug.IDebugger = debug("wahn:log");
const warn: debug.IDebugger = debug("wahn:warn");

/**
 * Policy Based Access Control Engine
 */
class Wahn {
    private policies: Policy[];

    constructor(options: WahnConstructorOptions) {
        // Policies can be added at runtime only
        this.policies = options.policies;
    }

    /**
     * Return all current policies
     */
    public getPolicies(): Policy[] {
        return this.policies;
    }

    /**
     * Return all polices attached to the roles provided
     * @param roles
     */
    private getPolicesForRole(roles: string[]): Policy[] {
        const policies: Policy[] = this.policies.filter((policy: Policy) => {
            const matchedPolicy: boolean = mm.some(roles, policy.roles, {
                nocase: true,
            });
            console.debug("matched policy", policy);
            if (matchedPolicy) {
                return policy;
            }
        });
        return policies;
    }

    /**
     * A callback for logging every request that fails.
     * @param options
     */
    private evaluationFailCallback({
        context,
        resource,
        reason,
    }: WahnEvaluationFailedOptions): void {
        console.log("Access Denied: ", reason);
    }
    /**
     *
     * @param options
     */
    public evaluateAccess({
        context,
        resource,
    }: WahnEvaluationOptions): boolean {
        try {
            // 1. Outcome defaults to: `deny`.
            let outcome: boolean = false;

            // 2. Find all applicable policies.
            const policies: Policy[] = this.getPolicesForRole(
                context.user.roles,
            );

            // Check if any of the policies have the resource
            const matchedPolicies: Policy[] = policies.filter(
                (policy: Policy) => {
                    let policyResourceMatch: boolean = false;
                    let policyConditionMatch: boolean = false;

                    // Does the policy match the current resource?
                    if (mm.some(resource, policy.resources)) {
                        log("Policy does match resource.");
                        policyResourceMatch = true;
                    } else {
                        log("Policy does not match resource.");
                        return false;
                    }
                    // Does the policy have a condition?
                    if (
                        typeof policy.conditions !== "undefined" &&
                        policy.conditions.length >= 1
                    ) {
                        // Do the condtions make this policy applicable?
                        policy.conditions.map((condition: PolicyCondition) => {
                            switch (condition.operator) {
                                case PolicyOperator.match:
                                    if (
                                        mm.isMatch(
                                            context[condition.field],
                                            `${condition.value}`,
                                        )
                                    ) {
                                        policyConditionMatch = true;
                                    }
                                    break;
                                case PolicyOperator.notMatch:
                                    if (
                                        mm.isMatch(
                                            context[condition.field],
                                            `${condition.value}`,
                                        ) === false
                                    ) {
                                        policyConditionMatch = true;
                                    }
                                    break;
                            }
                        });
                    } else {
                        // If there are no conditions on the policy, we can proceed
                        policyConditionMatch = true;
                    }
                    console.log({ policy });
                    if (policyResourceMatch && policyConditionMatch) {
                        return true;
                    }
                    return false;
                },
            );

            // 3. Evaluate all applicable polices.
            // a. If no policies are found: `outcome=deny`
            if (matchedPolicies.length === 0) {
                throw new EvaluationDenied("No policies matched the request.");
            }

            policies.forEach((policy: Policy) => {
                // 4. Is there an explict `deny` for the `resource`
                if (policy.action === PolicyAction.Deny) {
                    // a. If`yes`then`outcome=deny`and exit evaluation b. If`no` then continue.
                    throw new EvaluationDenied(
                        "Access has been explicty denied.",
                    );
                }

                // 5. Is there an `allow`?
                if (policy.action === PolicyAction.Allow) {
                    // a. If `yes` then `outcome=allow` and exit evaluation
                    outcome = true;
                } else {
                    throw new EvaluationDenied("Access has not been allowed.");
                }
            });
            // b. If `no` then continue.

            // 6. No `allow` found: `outcome=deny`
            return outcome;
        } catch (EvaluationDenied) {
            // console.log(EvaluationDenied.message);
            this.evaluationFailCallback({
                context,
                resource,
                reason: EvaluationDenied.message,
            });
            return false;
        }
    }
}

// [ Types ]----------------------------------------------------------------------------------------

type WahnConstructorOptions = {
    policies: Policy[];
};

type WahnEvaluationOptions = {
    context: RequestContext;
    resource: string;
};
type WahnEvaluationFailedOptions = {
    context: RequestContext;
    resource: string;
    reason: string;
};

type ContextUser = {
    id: string;
    ip?: string;
    // TODO: Filter wildcards from roles
    roles: string[];
};

type RequestContext = {
    user: ContextUser;
    [key: string]: any;
};

enum PolicyAction {
    Allow = "Allow",
    Deny = "Deny",
}

enum PolicyOperator {
    match = "match",
    notMatch = "notMatch",
}

type PolicyCondition = {
    field: string;
    // A dot path to the value on the context object
    value: string;
    operator: PolicyOperator;
};

type Policy = {
    resources: string[];
    action: PolicyAction;
    conditions?: PolicyCondition[];
    // Roles can have a glob
    roles: string[];
};

// [ Errors ]---------------------------------------------------------------------------------------

class ExtendableError extends Error {
    constructor(message) {
        super(message);
        this.name = this.constructor.name;
        this.stack = new Error(message).stack;
    }
}

class AuthorizationError extends ExtendableError {}
class EvaluationDenied extends ExtendableError {}

// [ Export ]---------------------------------------------------------------------------------------

export {
    Wahn,
    Policy,
    PolicyAction,
    PolicyCondition,
    RequestContext,
    PolicyOperator,
};
