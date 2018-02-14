import * as mm from "micromatch";
import * as debug from "debug";

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
    }: WahnEvaluationOptions): boolean | AuthorizationError {
        console.log({ context, resource });
        try {
            // First get all the polices applicable to this user
            const policies: Policy[] = this.getPolicesForRole(
                context.user.roles,
            );
            // Second, check if any of the policies have the resource
            // const resourceIsValid: boolean = mm.isMatch(resource, policies.resource)
            const matchedPolicies: Policy[] = policies.filter(
                (policy: Policy) => mm.some(resource, policy.resources),
            );
            console.log({ policies, matchedPolicies });
            return true;
        } catch (AuthorizationError) {
            throw AuthorizationError;
        }
    }
}

// [ Types ]----------------------------------------------------------------------------------------

type WahnConstructorOptions = {
    policies: Policy[];
};

type WahnEvaluationOptions = {
    context: PolicyContext;
    resource: string;
};

type ContextUser = {
    id: string;
    ip?: string;
    // TODO: Filter wildcards from roles
    roles: string[];
};

type PolicyContext = {
    user: ContextUser;
    [key: string]: any;
};

enum PolicyAction {
    Allow,
    Deny,
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

// [ Export ]---------------------------------------------------------------------------------------

export {
    Wahn,
    Policy,
    PolicyAction,
    PolicyCondition,
    PolicyContext,
    PolicyOperator,
};
