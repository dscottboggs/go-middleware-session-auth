# go-middleware-session-auth
A high-level middleware module for authenticated with session-based authentication. Plug-and-play in your existing API.

## REQUIRES SSL.
Any authentication plugin requires SSL to prevent MITM attacks.

### Usage
*TODO improve*
 - Implement a /login endpoint, which will prompt a user or application to submit user credentials
 - Implement an endpoint which accepts URL- or form-encoded credentials and calls sessionAuth.SignIn. Credentials should be submitted with the user's name in a field with the key/name "user" and the authorization token or password in a field with the key/name "token".
