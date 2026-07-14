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
  resolveCreatorRole: async (createdBy) => {
    const principal = await trustedAdminStore.findById(createdBy);
    return principal?.role ?? null;
  },
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

`createdBy` must be the authenticated server-side principal ID, never request
data. The required `resolveCreatorRole` callback binds that ID to the trusted
role used for authorization. `createdByRole` is only a compatibility assertion;
when present, it must exactly equal the resolved role or creation is denied and
audited. Authority callbacks must be bound functions or closures and must not
depend on `this`.

## Breaking migration

The authority adapter is required. Exact role spellings are preserved:
`SUPER_ADMIN` and `super-admin` no longer normalize to `super_admin`, and
unmapped local aliases deny. The planned release sequence is:

1. Publish the auth package containing `tinyland-rbac/1` and its reviewed role
   translation contracts.
2. Review application-local translation maps, including realm collisions such
   as a local `viewer` role.
3. Wire trusted creator-role resolvers and prove spoofed role assertions deny.
4. Publish the breaking invitation release with these required adapters.
5. Upgrade consumers and run packed-artifact cross-package parity tests before
   enabling invitation creation.

Because adapter provenance is package-instance-local, creating an adapter with
one installed copy and passing it to another is rejected during `configure()`.
