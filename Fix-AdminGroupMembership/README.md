# Fix-AdminGroupMembership

This script get all members of local admin group, removes disallowed users. It can create and add to admin group new admin account with password.

"Administrator", "Administrators" is language specific strings

Example:

| Local group Administrators members *BEFORE*| Local group Administrators members *AFTER*|
| --- | --- |
| user1 | |
| user2 | |
| Domain\DomainAdminGroup1 | Domain\DomainAdminGroup1 |
| Domain\DomainAdminGroup2 | Domain\DomainAdminGroup2 |
| Administrator | Administrator |
| | Admin | 



#### Kosarev Albert, 2017
