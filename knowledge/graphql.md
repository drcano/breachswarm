## GraphQL Abuse
Where: `/graphql`, `/graphiql`, `/api/graphql`, `/v1/graphql`, `/query`. Even when introspection is "off", field suggestions leak schema.
Introspection: POST `{"query":"{__schema{types{name fields{name args{name}}}}}"}`; if disabled, use clairvoyance/field-stuffing (error messages "Did you mean ...?" leak fields). `__type(name:"User"){fields{name}}`.
Auth / access bugs: call mutations/queries unauthenticated; IDOR via `node(id:"base64id")` global ids (decode/increment base64 `Type:1`); over-fetch sensitive fields the UI hides (`passwordHash`, `email`, `role`, internal notes).
Rate-limit / cost bypass: alias batching — `q1:login(...) q2:login(...) ...` sends N attempts in one request to beat per-request throttling (credential stuffing, OTP brute, coupon reuse).
DoS/complexity (report, don't run destructively): deeply nested cyclic queries; only note the vector.
Injection through resolvers: args flow into SQL/NoSQL/OS — apply those payloads inside GraphQL args.
Mutations to hunt: `updateUser`/`register` with extra fields (mass assignment: `role`,`isAdmin`), `createInvite`, `resetPassword`, file/import mutations.
Escalate: unauth admin mutation, cross-user IDOR, batched brute-force -> ATO.
