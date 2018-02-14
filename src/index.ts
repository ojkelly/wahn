// Policy Based Access Control Engine

/**
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

    public evaluateAccess(): boolean | AuthorizationError {
        return true;
    }
}

// [ Types ]----------------------------------------------------------------------------------------

type WahnConstructorOptions = {
    policies: Policy[];
};

type ContextUser = {
    id: string;
    ip?: string;
    roles: string[];
};

type PolicyContext = {
    user?: ContextUser;
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
    roles?: string[];
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
