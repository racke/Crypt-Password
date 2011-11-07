#!/usr/bin/perl
use strict;
use warnings;
use Test::More 'no_plan';

use FindBin '$Bin';
use lib "$Bin/../lib";
use_ok "Crypt::Password";

sub mock { bless {@_}, "Crypt::Password" };

{
    diag "set algorithm";
    my $c = mock;
    is $c->algorithm, "sha256", "default algorithm";
    is $c->{algorithm}, "sha256", "default algorithm";
    is $c->{algorithm_magic}, '$5$', "default algorithm magic";
    
    is $c->algorithm("sha512"), "sha512", "set algorithm (sha512)";
    is $c->{algorithm}, "sha512", "set algorithm (sha512)";
    is $c->{algorithm_magic}, '$6$', "set algorithm magic";
    
    is $c->algorithm, "sha512", "get algorithm";
    
    is $c->algorithm('$1$'), "md5", "set algorithm by magic (md5)";
    is $c->{algorithm}, "md5", "correct set algorithm (sha512)";
    is $c->{algorithm_magic}, '$1$', "correct set algorithm magic";
    
    is $c->algorithm, "md5", "get algorithm";
    
    is $c->algorithm('$3a$'), undef, "set unknown magic";
    is $c->{algorithm}, undef, "unknown magic";
    is $c->{algorithm_magic}, '$3a$', "magic";
}

{
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

{
    diag "crypt some text";
    
    my $c = password("hello0");
    like $c, qr/^\$5\$(........)\$...........+$/, "crypted";
    
    my $c2 = password("hello0");
    like $c2, qr/^\$5\$(........)\$...........+$/, "another crypted";
    isnt $c, $c2, "generated different salts";
    ok $c->check("hello0"), "validates";
    ok !$c->check("hello1"), "invalidates";
}

{
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
    diag "experiments";
    diag password("password", "salt");
    diag password("password", "sal");
    diag password("password", "sa");
    diag password("password", "s");
    diag password("password", "");
    diag password("password", "_3333salt");
    diag password("password", "_2222salt");
    diag password("password", "_2222salt");
    diag password("password", "a2222salt");
    diag password("password", "a2222salt");
    diag password("password", "_2222salt");
    diag password("password", "_2222sult");

diag `man crypt`;

1;
