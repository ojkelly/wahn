import * as mm from "micromatch";
import * as debug from "debug";

const info: debug.IDebugger = debug("wahn:info");
const log: debug.IDebugger = debug("wahn:log");
const warn: debug.IDebugger = debug("wahn:warn");

/**
 * Policy Based Access Control Engine
 * Define a policy as follows:
 *
 * {
 *  resouces: ['query::User:password'],
 *  action: 'deny',
 * }
 *
 * or
 *
 * {
 *  resources: ['query::User:*'],
 *  action: 'allow',
 *  condition: [
 *    {
 *      field: 'id',
 *      value: 'context.user.id'
 *    }
 *  ]
 * }
 */
class Wahn {
    // Policies can be added at runtime only
    private policies: Policy[];

    constructor(options: WahnConstructorOptions) {
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
            if (matchedPolicy) {
                return policy;
            }
        });
        return policies;
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

            console.log({ context, resource });

            // 2. Find all applicable policies.
            const policies: Policy[] = this.getPolicesForRole(
                context.user.roles,
            );

            // Check if any of the policies have the resource
            const matchedPolicies: Policy[] = policies.filter(
                (policy: Policy) => mm.some(resource, policy.resources),
            );

            // 3. Evaluate all applicable polices.
            console.log({ policies, matchedPolicies });

            // a. If no policies are found: `outcome=deny`
            if (matchedPolicies.length === 0) {
                throw new EvaluationDenied();
            }

            policies.forEach((policy: Policy) => {
                // 4. Is there an explict `deny` for the `resource`
                if (policy.action === PolicyAction.Deny) {
                    // a. If`yes`then`outcome=deny`and exit evaluation b. If`no` then continue.
                    throw new EvaluationDenied();
                }

                // 5. Is there an `allow`?
                if (policy.action === PolicyAction.Allow) {
                    // a. If `yes` then `outcome=allow` and exit evaluation
                    outcome = true;
                }
            });
            // b. If `no` then continue.

            // 6. No `allow` found: `outcome=deny`
            return outcome;
        } catch (EvaluationDenied) {
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
    is,
    isNot,
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
    condition?: [PolicyCondition];
    // Roles can have a glob
    roles: string[];
};

// [ Errors ]---------------------------------------------------------------------------------------

interface EvalError extends Error {}
interface AuthorizationError extends Error {}
class EvaluationDenied extends Error {}

// [ Export ]---------------------------------------------------------------------------------------

export {
    Wahn,
    Policy,
    PolicyAction,
    PolicyCondition,
    RequestContext,
    PolicyOperator,
};
