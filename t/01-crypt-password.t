#!/usr/bin/perl
use strict;
use warnings;
use Test::More 'no_plan';

use FindBin '$Bin';
use lib "$Bin/../lib";
use_ok "Crypt::Password";

sub mock { bless {@_}, "Crypt::Password" };

no warnings 'once', 'redefine';
my $glib = $Crypt::Password::glib;
diag "testing Crypt::Password (glib=".($glib ? "yes" : "no").")";
diag "os is $^O";
diag "/usr/share/doc/libc6 ".(-e "/usr/share/doc/libc6"?"is":"is not")." present";
*Crypt::Password::nothing = sub {
    diag "$_[0] = crypt('$_[1]', '$_[2]');";
};

if ($glib) {
    diag "set algorithm";
    my $c = mock;
    is $c->algorithm, "sha256", "default algorithm";
    is $c->{algorithm}, "sha256", "default algorithm";
    is $c->{algorithm_id}, '5', "default algorithm id";
    
    is $c->algorithm("sha512"), "sha512", "set algorithm (sha512)";
    is $c->{algorithm}, "sha512", "set algorithm (sha512)";
    is $c->{algorithm_id}, '6', "set algorithm id";
    
    is $c->algorithm, "sha512", "get algorithm";
    
    is $c->algorithm('1'), "md5", "set algorithm by id (md5)";
    is $c->{algorithm}, "md5", "correct set algorithm (sha512)";
    is $c->{algorithm_id}, '1', "correct set algorithm id";
    
    is $c->algorithm, "md5", "get algorithm";
    
    is $c->algorithm('3a'), undef, "set unknown id";
    is $c->{algorithm}, undef, "unknown id";
    is $c->{algorithm_id}, '3a', "id";
}

if ($glib) {
    diag "generate salt";
    my $c = mock;
    my $salt_1 = $c->salt;
    like $salt_1, qr/^\S{8}$/, "salt generated";
    $c = mock;
    my $salt_2 = $c->salt;
    like $salt_1, qr/^\S{8}$/, "salt generated";
    isnt $salt_1, $salt_2, "generated salts are different";
    
    is $c->salt("4fatness"), "4fatness", "salt set, returned";
    is $c->{salt}, "4fatness", "salt set, returned";
}

if ($glib) {
    diag "crypt some text";
    
    my $c = password("hello0");
    like $c, qr/^\$5\$(........)\$[a-zA-Z0-9\.\/]{43}$/, "crypted";
    
    my $c2 = password("hello0");
    like $c2, qr/^\$5\$(........)\$[a-zA-Z0-9\.\/]{43}$/, "another crypted";
    isnt $c, $c2, "generated different salts";
    ok $c->check("hello0"), "validates";
    ok !$c->check("hello1"), "invalidates";
    
    my $c3 = password("hello0", $c->salt);
    is($c, $c3, "same salt");
    ok($c3->check("hello0"), "yes indeed");
}
else {
    my $c = password("hello0");
    diag "non-glib password: $c";

    like $c, qr/^_.{8}.{11}$/, "salt comes out in semi-understandable format";
    
    ok($c->check("hello0"), "check the correct password");
    ok(!$c->check("helow"), "check the wrong password");
    is($c, password("hello0"), "check a new password");
    is($c, password("hello0", "DF"), "password with different salt? TODO");
    is($c, password("hello0", "_aa"), "password with different salt? TODO");
}
if ($glib) {
    diag "documented stuff";
    {
        my $hashed = password("password", "salt");
        like $hashed, qr/^\$5\$salt\$.{43}$/, "Default algorithm, supplied salt";
    }

    {
        my $hashed = password("password", "", "md5");
        like $hashed, qr/^\$1\$\$.{22}$/, "md5, no salt";
    }

    {
        my $hashed = password("password", undef, "sha512");
        like $hashed, qr/^\$6\$(.{8})\$.{86}$/, "sha512, invented salt";
    }
}

{
    *Crypt::Password::nothing = sub {
        diag "not _looks_crypted(): $_[0]"
            unless Crypt::Password->_looks_crypted($_[0]);
        my $p = password($_[0]);
        diag "not the same salt: $_[2] vs ".$p->salt
            unless $p->salt eq $_[2]
    };
    diag "experiments";
    diag password("password", "salt");
    diag password("password", "sal");
    diag password("password", "sa");
    diag password("password", "s");
    diag password("password", "s");
    diag password("password", "a");
    diag password("password", "a");
    diag password("passwod", "a");
    diag password("password", "");
    diag password("password", "_3333salt");
    diag password("password", "_2222salt");
    diag password("password", "_2222salt");
    diag password("password", "a2222salt");
    diag password("password", "a2222salt");
    diag password("password", "_2222salt");
    diag password("password", "_2222sult");
    diag "on $^O";
    diag "`man crypt`:\n". `man crypt` unless $^O eq "linux";
}

1;
