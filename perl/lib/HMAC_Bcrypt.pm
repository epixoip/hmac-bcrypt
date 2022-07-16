package HMAC_Bcrypt;

use strict;
use warnings;

use Exporter::Auto;

use Digest::SHA                   qw(hmac_sha512_base64);
use Crypt::Eksblowfish::Bcrypt    qw(bcrypt en_base64);
use Crypt::URandom                qw(urandom);
use String::Compare::ConstantTime qw(equals);

use constant BCRYPT_ID            => '2a';
use constant BCRYPT_COST          => 13;
use constant BCRYPT_SALT_BYTES    => 16;
use constant BCRYPT_PEPPER        => 'hmac_bcrypt';

##
# Generates a new hash from a plaintext password
#
# @param scalar password    plaintext password
# @param scalar settings    optional settings string (id + cost + salt)
# @param scalar pepper      optional pepper string
# @returns scalar           final hashed value
# @throws croak
##
sub hmac_bcrypt_hash {
    my ($password, $settings, $pepper) = @_;
    my ($cost, $salt);

    if (length $settings) {
        (undef, undef, $cost, $salt) = split /\$/, $settings;
        $salt = substr($salt, 0, 22);
    }

    unless (length $cost) {
        $cost = BCRYPT_COST;
    }

    unless (length $salt) {
        $salt = en_base64(
            urandom(BCRYPT_SALT_BYTES)
        );
    }

    unless (length $pepper) {
        $pepper = BCRYPT_PEPPER;
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
# @param scalar password    plaintext password
# @param scalar valid       stored hash value for comparison
# @param scalar pepper      optional pepper string
# @returns boolean
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
