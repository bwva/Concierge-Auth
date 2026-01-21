package Concierge::Auth v0.19.0;
use v5.40;

# ABSTRACT: Concierge authorization using Crypt::Passphrase

use Carp			qw/carp croak/;
use Fcntl			qw/:flock/;
use Crypt::Passphrase;
use parent			qw/Concierge::Auth::Generators/;

## Constants for validation
use constant {
    MIN_ID_LENGTH     	=> 2,
    MAX_ID_LENGTH     	=> 32,
    MIN_PASSWORD_LENGTH	=> 8,
    MAX_PASSWORD_LENGTH	=> 72,    # bcrypt limit
};

## Pre-compiled regex for ID validation - accepts email addresses
my $ID_ALLOWED_CHARS	= qr/^[a-zA-Z0-9._@-]+$/;
## Password file field separator
my $FIELD_SEPARATOR		= "\t";

## new: instantiate the auth object with a passwd file
## Complains if no file is provided unless the argument
## no_file => 1 is provided, but still instantiates
## the auth object; without a passwd file, the auth object
## can only provide the utility methods:
## encryptPwd(), gen_crypt_token(), gen_random_string(),
## gen_word_phrase(), gen_random_string(), gen_uuid,
## gen_token()<- deprecated
## A file may be designated after instantiation with
## the method setFile().
## Dies if it can't open/create a designated file.
## Complains if it can't set permissions on the file.
sub new {
	my ($class, $args)	= @_;

	my $self	= bless {
		auth => Crypt::Passphrase->new(
			encoder		=> 'Argon2',
			validators	=> [ 'Bcrypt' ],
		)
	}, $class;

	if ($args->{no_file}) {
		carp "Utilities only; no ID and password checks";
		# Still functional:
		return $self;
	}
	unless ($args->{file}) {
		carp "No auth file provided for ID and password checks";
		# Still functional:
		return $self;
	}

	if (-e $args->{file}) {
		open my $afh, "<", $args->{file} or
			croak ("Can't read auth file ($args->{file}). $! ");
		close $afh;
	} else {
		open my $afh, ">", $args->{file} or
			croak ("Can't open/create auth file ($args->{file}). $! ");
		close $afh;
	}

 	chmod 0600, $args->{file} or carp $!;
	$self->{auth}->{file}	= $args->{file};
	$self;
}

## Class Methods for Responses
## confirm, reject, reply
## NOT called with object arrow notation:
##    $self->reject # !WRONG
## Once instantiated, the auth object will not die/croak;
## Instead, all methods that check or validate respond with
##	`confirm ($msg)` # wantarray ? (1, $msg) : 1;
##  	or
##  `reject ($msg)`  # wantarray ? (0, $msg) : 0;
##  	or the more general
##  `reply ($bool, $msg)` # wantarray ? ($bool, $msg) : $bool
## Use explicit `return` to assure correct contrl flow:
## `return confirm($msg);`
## `return reply( $result, $msg);`
sub confirm {
	my $message = shift || "Auth confirmation";
	wantarray ? (1, $message) : 1;
}
sub reject {
	my $message = shift || "Auth rejection";
	wantarray ? (0, $message) : 0;
}
## First arg is 1|0 or other Perl true/false value
sub reply {
	my $bool	= shift // 0;
	my $message = shift || ( $bool ? "Auth confirmation" : "Auth rejection" );
	wantarray ? ($bool, $message) : $bool;
}

## Validations
sub validateID {
    my ($self, $id) = @_;

	return reject( "ID cannot be empty" )
		unless (defined $id && length($id) > 0);

    # Check length constraints
    return reject( sprintf(
    	"ID must be between %d and %d characters",
        MIN_ID_LENGTH, MAX_ID_LENGTH
    ) ) unless (
    	length($id) >= MIN_ID_LENGTH
    	 &&
    	length($id) <= MAX_ID_LENGTH
    );

    # Check pattern
    return reject( "ID contains invalid characters" )
    	unless ($id =~ $ID_ALLOWED_CHARS);

    return confirm;
}

sub validatePwd {
    my ($self, $password) = @_;

    # Check if password is defined and not empty
    return reject( "Password cannot be empty" )
        unless defined $password && length($password) > 0;

    # Check length constraints
    return reject( sprintf(
    	"Password must be between %d and %d characters",
        MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH
    ) ) unless (
    	length($password) >= MIN_PASSWORD_LENGTH
    	 &&
    	length($password) <= MAX_PASSWORD_LENGTH
    );

    return confirm;
}

sub validateFile {
    my ($self, $file) = @_;
    $file ||= $self->{auth}->{file};
    return ($file && -e $file && -r $file) ?
    	confirm( "Auth file OK"  )
    	: reject( "Auth file Not OK" );
}

## checkID: checks for a record with a specified user_id
sub checkID {
	my $self	= shift;
	my $id	= shift;

    my ($ok,$msg) = $self->validateID($id);
    return reject( $msg ) unless $ok;

 	my $pfile	= $self->pfile();
 	-e $pfile
 		or return reject( "checkID: No auth file");
	open my $pfh, "<", $pfile
		or return reject( "checkID: Can't read auth file" );
	flock($pfh, LOCK_SH) or do {
		close $pfh;
		return reject( "checkID: Can't lock file for reading: $!" );
	};
	my $sep		= $FIELD_SEPARATOR;
	while (<$pfh>) {
		if (/^$id$sep/) {
			close $pfh;
			return confirm( "ID OK" );
		}
	}
	close $pfh;
	return reject( "checkID: ID $id not confirmed" );
}

## deleteID: deletes a passwd file record with a specified user_id
sub deleteID {
	my $self	= shift;
	my $id	= shift;

    my @id		= $self->validateID($id);
    return reply( @id ) unless $id[0];

	my $sep		= $FIELD_SEPARATOR;
 	my $pfile	= $self->{auth}->{file} || '';
 	unless ( $pfile and -e $pfile ) {
 		return reject( "File $pfile no good" );
 	}
 	open my $fh, "+<", $pfile or return reject( "Cannot open file: $!" );
    flock($fh, LOCK_EX) or do {
		close $fh;
		return reject( "Cannot lock file: $!" );
	};
	my @lines	= <$fh>;

 	my $success	= 0;
	my @output;
	for my $line ( @lines ) {
		if ( $line =~ /^$id$sep/) {
			$success++;
			next;
		}
		push @output, $line;
	}
	unless (
		seek($fh, 0, 0)
		and truncate($fh, 0)
		and print $fh @output
		and close $fh
	) {
		close $fh;
		return reject( "deleteID: File update failed: $!" );
	}

	return reply($success, ($success ? $id : "ID $id not found to delete") );
}

## checkPwd: checks for a record with specified user_id & password
## returns boolean 1|0 = True|False
sub checkPwd {
	my $self	= shift;
	my $id		= shift;
	my $passwd	= shift;

    my @id		= $self->validateID($id);
    return reply( @id ) unless $id[0];
    my @pwd		= $self->validatePwd($passwd);
    return reply( @pwd ) unless $pwd[0];

	my $sep		= $FIELD_SEPARATOR;
 	my $pfile	= $self->{auth}->{file};

	open my $pfh, "<", $pfile
		or return reject( "checkPwd: Cannot open auth file: $!" );
	flock($pfh, LOCK_SH) or do {
		close $pfh;
		return reject( "checkPwd: Cannot lock file for reading: $!" );
	};
	while (<$pfh>) {
		if (/^$id$sep([^$sep]+)$sep\|/) {
			my $phash	= $1;
			close $pfh;
			# uses Crypt::Passphrase::verify_password
			if ($self->{auth}->verify_password($passwd,$phash)) {
				return confirm;
			} else {
				return reject( "checkPwd: Invalid password" );
			}
		}
	}
	close $pfh;
	return reject( "checkPwd: User ID not found" );
}

## setPwd: records a hashed password for a specified user_id
## Returns with a failure message if user_id already exists.
## Returns boolean 1|0 = True|False in scalar context
## Returns duple ( 1|0, 'string' ) in list context
## = (success|failure, ID or failure message)
sub setPwd {
	my $self	= shift;
	my $id		= shift	|| '';
	my $passwd	= shift	|| '';

    my @id		= $self->validateID($id);
    return reply( @id ) unless $id[0];
    my @pwd		= $self->validatePwd($passwd);
    return reply( @pwd ) unless $pwd[0];
	my @chk		= $self->checkID($id);
	return reject( "ID $id previously used" ) if $chk[0];

	my $phash	= $self->encryptPwd($passwd);
	my $sep		= $FIELD_SEPARATOR;
 	my $pfile	= $self->{auth}->{file};

	open my $pfh, ">>", $pfile
		or return reject( "setPwd: Cannot open auth file: $!" );
    flock($pfh, LOCK_EX) or do {
		close $pfh;
		return reject( "setPwd: Cannot lock file for writing: $!" );
	};
	print $pfh join( $sep => $id, $phash, "|\n") or do {
		close $pfh;
		return reject( "setPwd: Cannot write to file: $!" );
	};
	close $pfh or return reject( "setPwd: Cannot close file: $!" );
	return confirm( $id );
}

## resetPwd: records a new hashed password for a specified user_id
## returns boolean 1|0 = True|False in scalar context
## returns duple ( 1|0, 'string' ) in list context
## = (success|failure, ID or failure message)
sub resetPwd {
	my $self	= shift;
	my $id	= shift	|| '';
	my $passwd	= shift	|| '';

    my @id		= $self->validateID($id);
    return reply( @id ) unless $id[0];
    my @pwd		= $self->validatePwd($passwd);
    return reply( @pwd ) unless $pwd[0];

	my $phash	= $self->encryptPwd($passwd);

	my $sep		= $FIELD_SEPARATOR;
 	my $pfile	= $self->{auth}->{file} || '';
 	my @f		= $self->validateFile($pfile);
 	return reply( @f ) unless $f[0];

  	open my $fh, "+<", $pfile or return reject( "resetPwd: Cannot open file: $!" );
    flock($fh, LOCK_EX) or do {
		close $fh;
		return reject( "resetPwd: Cannot lock file: $!" );
	};
	my @lines	= <$fh>;

 	my $success	= 0;
	my @output;
	for my $line ( @lines ) {
		if ( $line =~ /^$id$sep/) {
			push @output => join( $sep => $id, $phash, "|\n" );
			$success++;
			next;
		}
		push @output, $line;
	}
	unless (
		seek($fh, 0, 0)
		and truncate($fh, 0)
		and print $fh @output
		and close $fh
	) {
		close $fh;
		return reject( "resetPwd: File update failed: $!" );
	}

	return reply($success, ($success ? $id : "ID $id not found to reset password") );
}

## Password file handling

## setFile: sets or changes the passwd file
## creates the file if necessary
sub setFile {
	my $self	= shift;
	my $file	= shift;

	return reject( "No filename" ) unless $file =~ /\S/;

	if (-e $file) {
		open my $afh, "<", $file or
			return reject(  "Can't read auth file ($file). $!" );
		close $afh;
	} else {
		open my $afh, ">", $file or
			return reject(  "Can't open/create auth file ($file). $!" );
		close $afh;
	}

 	chmod 0600, $file or carp $!;

 	if ( $self->validateFile($file) ) {
		$self->{auth}->{file}	= $file;
		return confirm( "Valid file" );
 	}

	return reject( "Invalid file" );
}

## rmFile: deletes the passwd file
sub rmFile {
	my $self	= shift;

 	my $pfile	= $self->{auth}->{file} || '';
 	unless ( $pfile and -e $pfile ) {
 		return reject( "No valid file to remove" );
 	}

	unless (unlink $pfile) {
		return reject( "Unable to unlink file: $! " );
	}

	$self->{auth}->{file} = '';

	return reply( $pfile, "Password file removed" );
}

sub clearFile {
	my $self	= shift;

	my ($pfile,$msg)	= $self->rmFile();
	return reply( 0, "No valid file to clear: $msg" ) unless $pfile;

	my ($ok,$setmsg)		= $self->setFile($pfile);
	return reject( "File not cleared: $setmsg" ) unless $ok;
    return confirm( "File cleared" );
}

## Utilities

## encryptPwd: returns encrypted password
sub encryptPwd {
	my $self	= shift;
	my $passwd	= shift;

    my @vp	= $self->validatePwd($passwd);
    return reply( @vp ) unless $vp[0];

	return $self->{auth}->hash_password($passwd);
}

## pfile: returns the passwd file, if any
sub pfile {
	my $self	= shift;
	return defined $self->{auth}->{file}
		? reply($self->{auth}->{file}, "Auth file" )
		: reject( "No auth file" );
}

## Generator method wrappers
## These methods wrap the plain subroutines from Concierge::Auth::Generators
## and return results using Auth.pm's reply response pattern

sub gen_uuid {
	my $self = shift;
	my ($uuid, $msg) = Concierge::Auth::Generators::gen_uuid(@_);

	return defined $uuid
		? reply($uuid, $msg)
		: reject("gen_uuid: Failed to generate UUID");
}

sub gen_token {
	goto &gen_random_token;
}

sub gen_crypt_token {
	my $self = shift;
	my ($token, $msg) = Concierge::Auth::Generators::gen_crypt_token(@_);

	return defined $token
		? reply($token, $msg)
		: reject("gen_crypt_token: Failed to generate crypt token");
}

sub gen_random_token {
	my $self = shift;
	my ($token, $msg) = Concierge::Auth::Generators::gen_random_token(@_);

	return defined $token
		? reply($token, $msg)
		: reject("gen_random_token: Failed to generate random token");
}

sub gen_random_string {
	my $self = shift;
	my ($string, $msg) = Concierge::Auth::Generators::gen_random_string(@_);

	return defined $string
		? reply($string, $msg)
		: reject("gen_random_string: Failed to generate random string");
}

sub gen_word_phrase {
	my $self = shift;
	my ($phrase, $msg) = Concierge::Auth::Generators::gen_word_phrase(@_);

	return defined $phrase
		? reply($phrase, $msg)
		: reject("gen_word_phrase: Failed to generate word phrase");
}

1;

__END__
