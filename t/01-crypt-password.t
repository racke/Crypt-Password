#!/usr/bin/perl
use strict;
use warnings;
use v5.10;
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
    like $c, qr/^\$_\S{7}\$\S{11}$/, "crypted: looks good";
    like password("hello0", "dg"), qr/^\$..\$\S{11}$/, "crypted: 2char supplied salt";

    diag "various salt inputs";
    # all invalid
    for my $salt ("dgdb", "a", "123456", "12345678") {
        eval { password("hello0", $salt) };
        like $@, qr/Bad salt input.+2 or 7 characters/, "wrong sized salt";
        undef $@;
    }
    for my $salt ("_a", "_bb") {
        eval { password("hello0", "_a") };
        like $@, qr/Bad salt input.+2-character salt cannot start with _/,
            "can't start with _";
    }

    # all valid
    my $p
    eval { $p = password('a', 'bbbbbbbb') };
    is $@, undef, "salt=8 no error";
    is $p, '$_bbbbbbbb$DJEHexiq9NI', "salt=8 crypt";
    undef $@;

    eval { $p = password('a', 'cc') };
    is $@, undef, "salt=2 no error";
    is $p, '$cc$DFDkLhMbQ7wZ.', "salt=2 crypt";
    undef $@;

    diag "checks, comparisons";
    ok($c->check("hello0"), "check the correct password");
    ok(!$c->check("helow"), "check the wrong password");
    isnt($c, password("hello0", "ga"), "compare a password - wrong salt");
    isnt($c, password("hello0", "DADAdada"), "compare a password - wrong salt");
    isnt($c, password("hello0", "etcetcet"), "compare a password - wrong salt");
    is($c, password("hello0", $c->salt), "compare a password - correct salt");
    isnt($c, password("hello1", $c->salt), "wrong password");
    
    isnt(password("007", "blahblah"), password("007", "BLAHblah"), "compare a password - wrong salt");
    is(my $c2 = password("123", "12341234"), password("123", "12341234"), "compare a password - correct salt");
    ok($c2->check("123"), "check the correct password");
    ok(!$c2->check("12341234"), "check the wrong password");
    ok(!$c2->check($c2), "can't just pass crypted stuff into check()");
    ok(!$c2->check(password("123", $c2->salt)), "can't just pass crypted stuff into check()");

    for ("ambiente", "lampshade", "guitar") {
        diag "$_ ". password($_, "12345555");
        diag "$_ ". password($_, "gi");
    }

    diag "reinstating a crypt object";
    my $c2_2 = password("$c2");
    is($c2, $c2_2, "stringified and back");
    is("$c2", "$c2_2", "stringified and back");
    ok($c2_2->check("123"), "stringified and back, check correct");
    ok(!$c2_2->check("23"), "stringified and back, check incorrect");
    ok($c2->check("123"), "123 still good");
    is($c2_2->salt, "123", "can extract the salt");
    ok(!password("$c2")->check('$_12341234$123'), "can't just pass crypted stuff into check()");
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

    {
        my $password = '$5$%RK2BU%L$aFZd1/4Gpko/sJZ8Oh.ZHg9UvxCjkH1YYoLZI6tw7K8';
        is $password, password($password), "password embodied by password()";
        isnt $password, crypt_password($password), "password recrypted by crypt_password()";

        # lately insane
        ok password($password) eq password($password), "comparison test";
        my $p1 = password($password);
        my $p2 = password($password);
        ok $p1 eq $p2, "comparison test";
    }
}

{
    *Crypt::Password::nothing = sub {
        diag "not _looks_crypted(): $_[0]"
            unless Crypt::Password->_looks_crypted($_[0]);
        local *Crypt::Password::nothing = sub {};
        say "$_[0]";
        my $p = password($_[0]);
        say "$p";
        $_[2] =~ s/^_//;
        $_[2] =~ s/^\$.*\$//;
        diag "not the same salt: $_[2] vs ".$p->salt
            unless $p->salt eq $_[2];
        diag "different hash: $_[0] vs $p"
            unless $p eq $_[0];
        diag "doesn't validate: $p $_[1]"
            unless $p->check($_[1]);
        diag "validone\n\n\n\n";
    };

    for my $salt ("aa", "12341234") {
        my $first;
        for (1..40) {
            my $p = Crypt::Password::_do_crypt("blah", $salt);
            $first ||= $p;
            if ($first ne $p) {
                diag "$first ! $p ($salt)";
            }
        }
    }

    diag "on $^O";
}

1;
