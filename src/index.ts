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
 *      value: context.user.id,
 *    }
 *  ]
 * }
 */

class Wahn {
  private policies: Policy[];

  constructor(options: WahnConstructorOptions) {
    this.policies = options.policies;
  }
}

type WahnConstructorOptions = {
  policies: Policy[];
};

type PolicyContext = {
  [key: string]: any;
};

enum PolicyAction {
  allow,
  deny
}

enum PolicyOperator {
  is,
  isNot
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
  condition: [PolicyCondition];
};

export {
  Wahn,
  Policy,
  PolicyAction,
  PolicyCondition,
  PolicyContext,
  PolicyOperator
};
