import { Policy } from "./index";

// [ Errors ]---------------------------------------------------------------------------------------

class ExtendableError extends Error {
    constructor(message) {
        super(message);
        this.name = this.constructor.name;
        this.stack = new Error(message).stack;
    }
}

class AuthorizationDeniedError extends ExtendableError {
    public name: string = "EvaluationDenied";
    public denyType: string = "Deny";

    constructor(public policy: Policy | null, public reason: string) {
        super(reason);
        this.policy = policy;
        this.reason = reason;
        this.denyType = policy && policy.denyType ? policy.denyType : "Deny";
    }
}

export { AuthorizationDeniedError, ExtendableError };
