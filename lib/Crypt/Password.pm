package Crypt::Password;
use Exporter 'import';
@EXPORT = ('password', 'crypt_password');
our $VERSION = "0.05";

use Carp;

use overload
    '""' => \&crypt,
    'eq' => \&crypt,
    'nomethod' => \&crypt;

# from libc6 crypt/crypt-entry.c
our %alg_to_id = (
    md5 => '1',
    blowfish => '2a',
    sha256 => '5',
    sha512 => '6',
);
our %id_to_alg = reverse %alg_to_id;

our $glib = (`man crypt`)[-1] !~ /FreeSec/;

our $definitely_crypt;

sub new {
    shift;
    password(@_);
}

sub crypt_password {
    local $definitely_crypt = 1;
    return password(@_);
}

sub password {
    my $self = bless {}, __PACKAGE__;

    carp "Got args: @_\n";
    
    $self->input(shift);
    
    unless ($self->{crypted}) {
        $self->salt(shift);
        
        $self->algorithm(shift); 
        
        $self->crypt();
    }

    $self
}

sub crypt {
    my $self = shift;
    
    $self->{crypted} ||= $self->_crypt
}

sub input {
    my $self = shift;
    $self->{input} = shift;
    if (!$definitely_crypt && $self->_looks_crypted($self->{input})) {
        $self->{crypted} = delete $self->{input}
    }
}

sub salt {
    my $self = shift;
    my $provided = shift;
    if (defined $provided) {
        $self->{salt} = $provided
    }
    else {
        $self->{salt} ||= do {
            if ($self->{crypted}) {
                if ($glib) {
                    (split /\$/, $self->{crypted})[2]
                }
                else {
                    # TODO unsure
                    $_ = $self->{crypted};
                    /^_/ &&
                        /^_(.{5,}).{11}$/
                    ||
                        /^(..).{11}$/;
                    $1 || carp "Failed to match: $_";
                }
            }
            else {
                $self->_invent_salt()
            }
        };
    }
}

sub algorithm {
    my $self = shift;
    $alg = shift;
    if ($alg) {
        $alg =~ s/^\$(.+)\$$/$1/;
        if (exists $alg_to_id{lc $alg}) {
            $self->{algorithm_id} = $alg_to_id{lc $alg};
            $self->{algorithm} = lc $alg;
        }
        else {
            # $alg will be passed anyway, it may not be known to %id_to_alg
            $self->{algorithm_id} = $alg;
            $self->{algorithm} = $id_to_alg{lc $alg};
        }
    }
    elsif (!$self->{algorithm}) {
        $self->algorithm($self->_default_algorithm)
    }
    else {
        $self->{algorithm}
    }
}

sub _crypt {
    my $self = shift;
    
    defined $self->{input} || croak "no input!";
    $self->{algorithm_id} || croak "no algorithm!";
    defined $self->{salt} || croak "invalid salt!";

    my $input = delete $self->{input};
    my $salt = $self->_form_salt();

    my $return = CORE::crypt($input, $salt);
    nothing($return, $input, $salt);
    return $return;
}

sub nothing { }

sub check {
    my $self = shift;
    my $plaintext = shift;
   
    my $salt = $self->_form_salt();
    carp "check: $plaintext $salt";
    my $new = CORE::crypt($plaintext, $self->_form_salt);
    carp "\n\nchecking: $new\nagainst:  $self\n";
    for ($new, "$self") {
        say "orded: ". join ",", map {ord} (split //)[0-6];
    }
    return $new eq "$self";
}

sub _form_salt {
    my $self = shift;
    my $s = $self->{salt};
    croak "undef salt!?" unless defined $s;
    if ($glib) {
        # glib
        if ($self->{algorithm_id}) {
            $s = sprintf('$%s$%s', $self->{algorithm_id}, $s);
        }
        else {
            # ->check(), alg and salt from ourselves
            $s = "$self";
        }
    }
    else {
        # FreeSec
        $s = "_$s" unless length($s) == 2 || length($s) == 0;
    }
    return $s;
}

our @valid_salt = ( "/", ".", "a".."z", "A".."Z", "0".."9" );

sub _invent_salt {
    join "", map { $valid_salt[rand(@valid_salt)] } 1..8;
}

sub _looks_crypted {
    my $self = shift;
    my $string = shift;
    if ($string) {
        if ($glib) {
            $string =~ m{^\$.+\$.*\$.+$}
        }
        else {
            # TODO string length = 13? bah
            $string =~ /^(_.{5,}|..).{11}$/
        }
    }
}

sub _default_algorithm {
    "sha256"
}

1;

__END__

=head1 NAME

Crypt::Password - Unix-style, Variously Hashed Passwords

=head1 SYNOPSIS

 use Crypt::Password;
 
 my $hashed = password("newpassword");
 
 $user->set_password($hashed);
 
 if (password($from_database)->check($password_from_user)) {
     # authenticated
 }

 my $definitely_crypted_just_then = crypt_password($maybe_already_crypted);

 # you also might want to
 password($a) eq password($b)
 # WARNING: password() will embody but not crypt an already crypted string
 #          if you are checking something from the outside world, use check()

 # imagine stealing a crypted string and using it as a password. it happens.

 # WARNING: the following applies to glibc's crypt() only
 #          Non-Linux systems beware.

 # Default algorithm, supplied salt:
 my $hashed = password("password", "salt");
 
 # md5, no salt:
 my $hashed = password("password", "", "md5");
 
 # sha512, invented salt: 
 my $hashed = password("password", undef, "sha512");

=head1 DESCRIPTION

This is just a wrapper for perl's C<crypt()>, which can do everything you would
probably want to do to store a password, but this is to make usage easier.
The object stringifies to the return string of the crypt() function, which is
(B<on Linux/glibc>) in Modular Crypt Format:

 # scalar($hashed):
 #    v digest   v hash ->
 #   $5$%RK2BU%L$aFZd1/4Gpko/sJZ8Oh.ZHg9UvxCjkH1YYoLZI6tw7K8
 #      ^ salt ^

That you can store, etc, retrieve then give it to C<password()> again to
C<-E<gt>check($given_password)>.

Not without some danger, so read on, you could also string compare it to the
output of another C<password()>, as long as the salt is the same. Actually, if
you are running on B<Linux/glibc> you can pass the first password as the salt
to the second and it will get it right. Anyway, the danger:

If the given string is already hashed it is assumed to be okay to use it as is.
So if you are checking something from the outside world, C<-E<gt>check($it)>
against the thing you can trust. You could also use C<crypt_password()>, which
will definitely crypt its input.

This means simpler code and users can supply pre-hashed passwords initially, but
if you do it wrong a stolen hash could be used as a password, so buck up your ideas.

If you aren't running B<Linux/glibc>, everything after the WARNING in the synopsis
is dubious as. If you've got insight into how this module can work better on
B<Darwin/FreeSec> I would love to hear from you.

=head1 FUNCTIONS

=over

=item password ( $password [, $salt [, $algorithm]] )

Constructs a Crypt::Password object.

=item crypt_password ( $password [, $salt [, $algorithm]] )

Same as above but will definitely crypt $password, even if it looks crypted.
See warning labels.

=back

=head1 METHODS

=over

=item check ( $another_password )

Checks the given password hashes the same as that this object represents.

=item crypt

Returns the crypt string, same stringifying the object.

=item salt

Returns the salt.

=back

=head1 KNOWN ISSUES

Cryptographic functionality depends greatly on your local B<crypt(3)>.
Old Linux may not support sha*, many other platforms only support md5, or that
and Blowfish, etc.

Functionality on FreeSec's crypt is particularly crap.

=head1 SUPPORT, SOURCE

If you have a problem, submit a test case via a fork of the github repo.

 http://github.com/st3vil/Crypt-Password

=head1 AUTHOR AND LICENCE

Code by Steve Eirium, L<nostrasteve@gmail.com>, idea by Sam Vilain,
L<sam.vilain@catalyst.net.nz>.  Development commissioned by NZ
Registry Services.

Copyright 2009, NZ Registry Services.  This module is licensed under
the Artistic License v2.0, which permits relicensing under other Free
Software licenses.

=head1 SEE ALSO

L<Digest::SHA>, L<Authen::Passphrase>, L<Crypt::SaltedHash>

=cut

