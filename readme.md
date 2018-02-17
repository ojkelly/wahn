# Wahn

**Policy Machine for Role Based Access Control**

## Usage

```typescript
import {
    Wahn,
    Policy,
    PolicyAction,
    RequestContext,
    PolicyOperator,
} from "whan";

// In your request you will have information about the user, their roles,
// and possibly other information about their session, like their
// OS or IP
// You pass these to `wahn` during your evaluateAccess check via the
// context object
const context: RequestContext = {
    user: {
        id: "UserId",
        roles: ["authenticated user"],
    },
};

// Define a policy
const policy: Policy = {
    // This is a simple policy with only one resource
    resources: ["test::resource"],
    // You can either Allow or Deny access
    action: policyAction.Allow,
    // This policy is then attached to the role `authenticated user`
    roles: ["authenticated user"],
};

// Now we create a Wahn
const wahn: Wahn = new Wahn({
    policies: [policy],
});

// Now lets check if our user has access to our test resource
const hasAccess: boolean = wahn.evaluateAccess({
    context,
    resource: "test::resource",
});
// hasAccess === true

// Now lets check if our user has access to a different resource
const hasAccess: boolean = wahn.evaluateAccess({
    context,
    resource: "AResourceTheUserCannotAccess",
});
// hasAccess === false
```

### Policy Object

You can view the `Policy` type detailed type information, below is the plain JSON version.

```JSON
{
    // A action represents the object an action is being performed on.
    // In the example below we have two GraphQL paths.
    // The resource and verb are both combined here.
    actions: [
      "query::User:*",
      "query::Posts:*",
      "mutation::createPost"
    ]

    // There are only two types of effects on the policy Allow and Deny
    effect: "Allow",

    // Conditions allow futher refinement of the policy, and final outcome.

    conditions: [
      {
        // A dot path to the value on the context object
        field: "userId",
        operator: "match", // or "notMatch"
        object: "resource",
        value: "user.id",

      }
    ],

    // Resources are whats being actioned on
    resources: [
      // User and all it's fields
      "User:*",
      // Or a wildcard for everything
      "*"
    ]

    // Roles are what the policy is attached to
    roles: [
      "authenticated user",
      "subscriber"
    ]
}
```

## Evalutation Process

1. Outcome defaults to: `deny`.
2. Find all applicable policies.
   a. If none found: `outcome=deny`
3. Evaluate all applicable polices.
4. Is there an explict `deny` for the `resource`?
   a. If`yes`then`outcome=deny`and exit evaluation b. If`no` then continue.
5. Is there an `allow`?
   a. If `yes` then `outcome=allow` and exit evaluation
   b. If `no` then continue.
6. No `allow` found: `outcome=deny`
