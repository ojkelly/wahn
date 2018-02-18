import * as mm from "micromatch";
import * as debug from "debug";

import { AuthorizationError, EvaluationDeniedError } from "./errors";
import { evaluateAccess, matchPolicies } from "./evaluate";

const info: debug.IDebugger = debug("wahn:info");
const log: debug.IDebugger = debug("wahn:log");
const warn: debug.IDebugger = debug("wahn:warn");

/**
 * Policy Based Access Control Engine
 */
class Wahn {
    private policies: Policy[];

    private loggingCallback: LoggingCallback | undefined;

    constructor(options: WahnConstructorOptions) {
        this.policies = options.policies;

        if (typeof options.loggingCallback === "function") {
            this.loggingCallback = options.loggingCallback;
        }
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

    public evaluateAccess({
        context,
        action,
        resource,
    }: WahnEvaluationOptions): boolean {
        try {
            // 1. Outcome defaults to: `deny`.
            let outcome: boolean = false;

            // 2. Find all applicable policies.
            const policies: Policy[] = this.getPolicesForRole(
                context.user.roles,
            );

            outcome = evaluateAccess({
                policies,
                context,
                action,
                resource,
            });

            return outcome;
        } catch (EvaluationDeniedError) {
            // console.log(EvaluationDeniedError.message);
            this.evaluationFailCallback({
                policyId: EvaluationDeniedError.policyId,
                context,
                action,
                resource,
                reason: EvaluationDeniedError.reason,
            });
            return false;
        }
    }

    /**
     * A callback for logging every request that fails.
     * @param options
     */
    private evaluationFailCallback({
        context,
        action,
        reason,
        resource,
        policyId,
    }: WahnEvaluationFailedOptions): void {
        info("evaluationFailCallback", { policyId, context, action, reason });
        if (typeof this.loggingCallback === "function") {
            this.loggingCallback({
                policyId,
                context,
                action,
                reason,
                resource,
            });
        }
    }
}

// [ Types ]----------------------------------------------------------------------------------------

type WahnConstructorOptions = {
    policies: Policy[];
    loggingCallback?: LoggingCallback;
};

type WahnEvaluationOptions = {
    context: RequestContext;
    action: string;
    resource: string;
};
type WahnEvaluationFailedOptions = {
    policyId: string;
    context: RequestContext;
    resource: string;
    action: string;
    reason: string;
};

type ContextUser = {
    id: string;
    roles: string[];
    [key: string]: any;
};

type RequestContext = {
    user: ContextUser;
    resource?: any;
    request?: {
        ip?: string;
        [key: string]: any;
    };
    [key: string]: any;
};

enum PolicyEffect {
    Allow = "Allow",
    Deny = "Deny",
}

enum PolicyOperator {
    match = "match",
    notMatch = "notMatch",
    lessThan = "lessThan",
    greaterThan = "greaterThan",
}

type PolicyCondition = {
    // A dot path to the value on context
    field: string;

    // Expected value
    expected?: string | string[];

    // A dot path to the context object
    expectedOnContext?: string | string[];

    operator: PolicyOperator;
};

type Policy = {
    actions: string[];
    resources: string[];
    // id must be unqiue
    id: string;
    effect: PolicyEffect;
    // Multiple conditions are evaluated as AND (ie all conditions must be true)
    conditions?: PolicyCondition[];
    // Roles can have a glob
    roles: string[];
};

interface LoggingCallback {
    (LoggingCallbackLog): void;
}

type LoggingCallbackLog = {
    policyId: string;
    context: RequestContext;
    action: string;
    reason: string;
    resource: string;
};

// [ Export ]---------------------------------------------------------------------------------------

export {
    Wahn,
    // Policy Exports
    Policy,
    PolicyEffect,
    PolicyCondition,
    PolicyOperator,
    // Logging Exports
    LoggingCallback,
    LoggingCallbackLog,
    RequestContext,
    ContextUser,
    WahnConstructorOptions,
    WahnEvaluationOptions,
};
