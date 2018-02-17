// [ Errors ]---------------------------------------------------------------------------------------

class ExtendableError extends Error {
    constructor(message) {
        super(message);
        this.name = this.constructor.name;
        this.stack = new Error(message).stack;
    }
}

class AuthorizationError extends ExtendableError {}
class EvaluationDeniedError extends ExtendableError {
    public name: string = "EvaluationDenied";
    constructor(public policyId: string, public reason: string) {
        super(reason);
        this.policyId = policyId;
        this.reason = reason;
        this.stack = new Error().stack;
    }
}

export { AuthorizationError, EvaluationDeniedError };
