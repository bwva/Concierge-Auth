# Concierge::Auth

Concierge authorization using Crypt::Passphrase - a production-ready authentication and authorization framework.

## VERSION

v0.5.1

## DESCRIPTION

Concierge::Auth provides comprehensive user authentication and authorization capabilities using Crypt::Passphrase for secure password management. It supports file-based user storage and token generation, and is designed for substitution with other backends (LDAP, OAuth, etc.) that satisfy the same contract.

## FEATURES

- **Secure Password Management**: Argon2 encoder with Bcrypt fallback validators
- **User Authentication**: File-based user authentication with encrypted passwords
- **Token Generation**: Generate cryptographically secure tokens and UUIDs
- **Password Utilities**: Password strength validation, random string generation
- **File Management**: Secure user file operations with proper locking
- **Generator Architecture**: Extensible generator system for tokens and identifiers

## MODULE STRUCTURE

- **Concierge::Auth** - Backend factory / facade
- **Concierge::Auth::Base** - Backend contract that all backends implement
- **Concierge::Auth::Pwd** - Built-in password-file backend
- **Concierge::Auth::Generators** - Token and identifier generation system

## INSTALLATION

From source:
```bash
perl Makefile.PL
make
make test
make install
```

From CPAN:
```bash
cpanm Concierge::Auth
```

## QUICK START

```perl
use Concierge::Auth;

my $auth = Concierge::Auth->new(
    backend => 'Concierge::Auth::Pwd',
    file    => '/path/to/users.passwd',
);

my $result = $auth->enroll($user_id, $password);
my $result = $auth->authenticate($user_id, $password);
my $result = $auth->is_id_known($user_id);
my $result = $auth->change_credentials($user_id, $new_password);
my $result = $auth->revoke($user_id);

# Generators -- work with or without a file
# (backend => 'Concierge::Auth::Pwd', no_file => 1)
my $token = $auth->gen_random_token();
my $uuid  = $auth->gen_uuid();
```

Each of the five core methods above returns a hashref: `{ success => 1, ... }`
on success, or `{ success => 0, message => '...' }` on failure. See
`Concierge::Auth::Base` for the full contract.

The generator methods (`gen_random_token`, `gen_uuid`, etc.) are different:
they follow a `wantarray` `(value)` / `(value, message)` dual-return
convention rather than returning a hashref, so context matters:

```perl
my ($token, $msg) = $auth->gen_random_token();  # list context
my $token          = $auth->gen_random_token();  # scalar context: $msg discarded
```

## REQUIREMENTS

- Perl 5.36 or higher
- Carp
- Fcntl
- Crypt::Passphrase
- Crypt::PRNG
- Time::HiRes
- parent
- Exporter
- Test2::V0 (for testing)

## PASSWORD SECURITY

Concierge::Auth uses Crypt::Passphrase with:
- **Primary Encoder**: Argon2 (memory-hard, resistant to GPU/ASIC attacks)
- **Fallback Validators**: Bcrypt (for backward compatibility)
- **Password Length**: 8-72 characters (bcrypt limit)
- **User ID Validation**: 2-32 characters, alphanumeric plus . _ @ -

## PRODUCTION USE

Concierge::Auth is actively used in production environments. Key features for production:

- **File Locking**: Proper flock() support for concurrent access
- **Secure Defaults**: Argon2 encoder with reasonable defaults
- **Error Handling**: Comprehensive error checking and reporting
- **Token Security**: Cryptographically secure random token generation
- **Flexible Architecture**: Works with or without password files

## INTEGRATION

Concierge::Auth integrates with the Concierge ecosystem:
- **Concierge::Users** - User data management
- **Concierge::Sessions** - Session management

These modules together form the core of the Concierge service layer, providing:
- Authentication (Concierge::Auth)
- User data management (Concierge::Users)
- Session tracking (Concierge::Sessions)

## EXAMPLES

The `examples/` directory currently contains one example:

- `1-custom-backend-ldap.pl` - sketch of a directory-backed (LDAP)
  `Concierge::Auth::Base` implementation

More examples covering the built-in `Concierge::Auth::Pwd` backend and
generator usage are planned. See `examples/README.md` for details.

## ARCHITECTURE

Concierge::Auth follows a service layer pattern:
- **Constructor**: May die on fatal errors (missing backend, file permissions)
- **Core contract methods**: Never die, always return a `{ success => ... }`
  hashref (see `Concierge::Auth::Base`)
- **Generator methods**: Never die, use a `wantarray` dual-return convention
  (see `Concierge::Auth::Generators`)

The module uses modern Perl practices:
- v5.36+ syntax
- Type validation
- Consistent error handling
- Clear separation of concerns

## AUTHOR

Bruce Van Allen <bva@cruzio.com>

## LICENSE

Artistic License 2.0

## SEE ALSO

- Concierge::Users
- Concierge::Sessions
- Crypt::Passphrase
- Crypt::PRNG

## CHANGES

See Changes file for revision history.
