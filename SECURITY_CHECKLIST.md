# Security checklist and test record

| Area | Control | Verification |
|---|---|---|
| Authentication | Password hashing and minimum 12-character password | Registration rejects short passwords; login verifies the hash. |
| Session | HTTPOnly + SameSite cookies; session regenerated after login | Login clears the old session before setting identity and a new CSRF token. |
| Injection | Parameterized SQL | User input is passed as SQLite parameters, never string-concatenated into SQL. |
| CSRF | Token required for every POST action | Invalid CSRF token returns HTTP 400. |
| Authorization | Login/admin decorators and ownership checks | Anonymous listing/transfer/message access returns HTTP 403; admin APIs require `is_admin`. |
| Stored XSS | Jinja autoescaping | Product and message fields are rendered through Jinja rather than marked safe. |
| Business logic | Positive amounts, balance test, database transaction | A transfer cannot overdraw the sender and debit/credit execute in one transaction. |
| Abuse response | User/product blocking | Blocked users/products are hidden, blocked accounts cannot use protected features, and blocked receivers cannot be messaged. |

Smoke test performed on 2026-07-23:

1. Registered seller and buyer accounts.
2. Logged in as seller and listed a product.
3. Logged in as buyer, confirmed that product search shows the listing, and transferred 1,000 KRW.
4. Submitted a transfer with an invalid CSRF token and confirmed HTTP 400.
5. Created an administrator with the Flask CLI and confirmed that the administration page and block actions require an administrator session and CSRF token.
6. Confirmed that a message to a blocked recipient is rejected with HTTP 403.
