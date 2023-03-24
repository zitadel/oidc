This file is a place to note backwards-incompatible changes that will be present
in the next major release.

Here are planned changes.

- `op.CanSetUserinfoFromRequest` will be removed.
- `op.SetUserinfoFromScopes` will be replaced with `op.SetUserinfoFromRequest`.
  You can switch to `op.SetUserinfoFromRequest` immediately and have an empty 
  implementation of `op.SetUserinfoFromScopes`. To get the subject and client 
  (current parameters to `op.SetUserinfoFromScopes`) in `op.SetUserinfoFromRequest`,
  call `token.GetSubject()` and `request.GetClientID` respectively.

