# Wahn

[![View on npm](https://img.shields.io/npm/v/wahn.svg)](https://npmjs.org/packages/wahn)
[![npm downloads](https://img.shields.io/npm/dm/wahn.svg)](https://npmjs.org/packages/wahn)
[![Dependencies](https://img.shields.io/david/ojkelly/wahn.svg)](https://david-dm.org/ojkelly/wahn)
[![Build Status](https://travis-ci.org/ojkelly/wahn.svg?branch=master)](https://travis-ci.org/ojkelly/wahn)
[![codecov](https://codecov.io/gh/ojkelly/wahn/branch/master/graph/badge.svg)](https://codecov.io/gh/ojkelly/wahn)
[![NSP Status](https://nodesecurity.io/orgs/ojkelly/projects/62f4946c-226b-4338-a092-8a878eb686c7/badge)](https://nodesecurity.io/orgs/ojkelly/projects/62f4946c-226b-4338-a092-8a878eb686c7)[![Known Vulnerabilities](https://snyk.io/test/npm/wahn/badge.svg)](https://snyk.io/test/npm/wahn)

**Policy Machine for Role Based Access Control**

Designed for use with the [Bunjil](https://github.com/ojkelly/bunjil) GraphQL server, Wahn is flexible policy based authorization engine. It is inpsired by other policy engines including AWS IAM.

## Getting Started

`yarn add wahn`

`npm install wahn`

### Usage

```typescript
// Typescript
import { Wahn, Policy, PolicyAction, PolicyOperator } from "wahn";

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
```

```javascript
// javascript
import { Wahn } from "wahn";

// Define a policy
const policy = {
    // This is a simple policy with only one resource
    resources: ["test::resource"],
    // You can either `Allow` or `Deny` access
    action: "Allow",
    // This policy is then attached to the role `authenticated user`
    roles: ["authenticated user"],
};

// Now we create a Wahn
const wahn = new Wahn({
    policies: [policy],
});
```

Now you have an `Wahn` instance with policies, you can attempt to access something.

```typescript
// typescript
import { RequestContext } from "wahn";

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

```javascript
//javascript
import { RequestContext } from "whan";

// In your request you will have information about the user, their roles,
// and possibly other information about their session, like their
// OS or IP
// You pass these to `wahn` during your evaluateAccess check via the
// context object
const context = {
    user: {
        id: "UserId",
        roles: ["authenticated user"],
    },
};

// Now lets check if our user has access to our test resource
const hasAccess = wahn.evaluateAccess({
    context,
    resource: "test::resource",
});
// hasAccess === true

// Now lets check if our user has access to a different resource
const hasAccess = wahn.evaluateAccess({
    context,
    resource: "AResourceTheUserCannotAccess",
});
// hasAccess === false
```

### Policy Object

You can view the `Policy` type detailed type information, below is the plain JSON version.

```javascript
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
        field: "${user.id}",
        operator: "match", // or "notMatch"
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

### Conditions

Conditions provide a powerful way to refine access on a Policy. `wahn` makes no assumptions about
your implementation, and so the implementation of conditions is partially dependent on your impelmenation.

A condition scopes a Policy to values you provide in the context object.

When you define a `Condition` there are 3 parameters:

* `field`: a dot path to the key on your `context` object.
* `expected`: the value you expect to see (hard coded into the policy)
* `expectedOnContext`: a dot path to the expected value on your `context` object.
  value on the context object
* `operator`: `match`, `notMatch`, `lessThan`, `greaterThan`

## Running the tests

Use `yarn tests` or `npm run tests`.

Tests are written with `ava`, and we would strongly like tests with any new functionality.

### Performance

`wahn` needs to be as performant as possible. We use `wahn` to keep track of performance
changes. Any new functionality cannot increase the performance beyond resonable limits.

## Deployment

Wahn could either be integrated into your application, or setup as a
standalone server.

## Contributing

Please read [CONTRIBUTING.md](https://github.com/ojkelly/wahn/CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull requests to us.

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/ojkelly/wahn/tags).

## Authors

* **Owen Kelly** - [ojkelly](https://github.com/ojkelly)

## License

This project is licensed under the MIT License - see the [LICENSE.md](https://github.com/ojkelly/wahn/LICENSE.md) file for details

## Acknowledgments

* Inspired in part by AWS IAM, NIST RBAC
* [Behind the name](<https://en.wikipedia.org/wiki/Crow_(Australian_Aboriginal_mythology)>)
