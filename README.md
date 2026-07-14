# @tummycrypt/tinyland-invitation

Databaseless invitation creation and acceptance for Tinyland applications.

## Role authority

Invitation creation has no built-in role hierarchy. Consumers must adapt a
reviewed `tinyland-rbac/1` authority explicitly:

```ts
import { canManageRole, RBAC_AUTHORITY } from '@tummycrypt/tinyland-auth';
import {
  configure,
  createInvitationRoleAuthority,
} from '@tummycrypt/tinyland-invitation';

configure({
  // ...storage, crypto, audit, and URL dependencies...
  roleAuthority: createInvitationRoleAuthority({
    version: RBAC_AUTHORITY.version,
    canManageRole,
  }),
});
```

`configure()` rejects missing, stale, or non-factory adapters. A throwing
authority denies invitation creation and emits an
`INVITATION_ROLE_AUTHORITY_ERROR` audit event. The factory proves that the
wrapper came from the same installed package instance and is immutable; it
does not prove that the consumer-supplied callback implements reviewed policy.
The code that calls `configure()` remains the policy trust boundary.

The optional `canCreateInviteForRole` hook runs only after the authority allows
a role pair and can therefore veto an invitation, but cannot elevate one.

Applications with local role vocabularies must translate those roles through a
reviewed auth-package translation contract inside `canManageRole`. Unmapped
roles must remain denied.

`createdByRole` is asserted by the calling application. Routes must derive it
from an authenticated server-side principal, never request data. Authority
callbacks must be bound functions or closures and must not depend on `this`.

## Breaking migration

The authority adapter is required. Exact role spellings are preserved:
`SUPER_ADMIN` and `super-admin` no longer normalize to `super_admin`, and
unmapped local aliases deny. The planned release sequence is:

1. Publish the auth package containing `tinyland-rbac/1` and its reviewed role
   translation contracts.
2. Review application-local translation maps, including realm collisions such
   as a local `viewer` role.
3. Publish the breaking invitation release with this required adapter.
4. Upgrade consumers and run packed-artifact cross-package parity tests before
   enabling invitation creation.

Because adapter provenance is package-instance-local, creating an adapter with
one installed copy and passing it to another is rejected during `configure()`.
