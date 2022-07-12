package HMAC_Bcrypt;

use strict;
use warnings;

use Exporter::Auto;

use Crypt::Eksblowfish::Bcrypt qw(bcrypt en_base64);
use String::Compare::ConstantTime qw(equals);
use Digest::SHA qw(hmac_sha512_base64);
use Crypt::URandom qw(urandom);

use constant BCRYPT_ID         => '2a';
use constant BCRYPT_COST       => 13;
use constant BCRYPT_SALT_BYTES => 16;
use constant BCRYPT_PEPPER     => 'hmac_bcrypt';

##
# Generates a new hash from a plaintext password
#
# @param password  scalar containing plaintext password
# @param settings  scalar containing settings string or undef
# @param pepper    scalar containing pepper string or undef
# @returns         scalar containing hashed password
##

sub hmac_bcrypt_hash {
    my ($password, $settings, $pepper) = @_;
    my ($cost, $salt);

    if ($settings) {
        (undef, undef, $cost, $salt) = split /\$/, $settings;
    }

    unless (length $cost) {
        $cost = BCRYPT_COST;
    }

    unless (length $salt && length $salt >= 22) {
        $salt = en_base64(
            urandom(BCRYPT_SALT_BYTES)
        );
    } else {
        $salt = substr($salt, 0, 22);
    }

    $settings = sprintf('$%2s$%02d$%s', BCRYPT_ID, $cost, $salt);

    my $pre_hash  = hmac_sha512_base64($password, $pepper);
    my $mid_hash  = bcrypt($pre_hash, $settings);
    my $post_hash = hmac_sha512_base64($mid_hash, $pepper);

    return $settings . $post_hash;
}

##
# Compares password to stored hash value
#
# @param password   scalar containing plaintext password
# @param valid      scalar containing stored hash value
# @param pepper     scalar containing pepper string or undef
# @returns          boolean
##

sub hmac_bcrypt_verify {
    my ($password, $valid, $pepper) = @_;

    my $hash = hmac_bcrypt_hash($password, $valid, $pepper);
    return equals($hash, $valid);
}

INIT {
    my $pass   = 'test-password';
    my $pepper = 'test-pepper';
    
    my $hash = hmac_bcrypt_hash($pass, undef, $pepper);
    
    unless (hmac_bcrypt_verify($pass, $hash, $pepper)) {
        die "HMAC_Bcrypt module failed sanity check!";
    }
}

1;
