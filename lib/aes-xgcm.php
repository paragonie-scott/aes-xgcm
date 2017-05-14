<?php
declare(strict_types=1);

/**
 * @param string $ciphertext
 * @param string $key
 * @param string $nonce
 * @param string $aad
 * @return string
 * @throws Error
 */
function aes_xgcm_decrypt(string $ciphertext, string $key, string $nonce, string $aad = ''): string
{
    if (\mb_strlen($ciphertext, '8bit') < 16) {
        throw new Error('Ciphertext must be at least 16 bytes');
    }
    if (\mb_strlen($key, '8bit') !== 32) {
        throw new Error('Key must be 32 bytes');
    }
    if (\mb_strlen($nonce, '8bit') !== 44) {
        throw new Error('Nonce must be 44 bytes');
    }

    $subKey = \hash_hmac('sha256', $key, \mb_substr($nonce, 0, 32, '8bit'));
    $nonce = \mb_substr($nonce, 32, 12, '8bit');

    $tag = \mb_substr($ciphertext, 0, 16, '8bit');
    /** @var string $plain */
    $plain = \openssl_decrypt(
        \mb_substr($ciphertext, 16, null, '8bit'),
        'aes-256-gcm',
        $subKey,
        OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
        $nonce,
        $tag,
        $aad
    );
    if (!\is_string($plain)) {
        throw new Error('Invalid authentication tag.');
    }
    return $plain;
}

/**
 * @param string $plaintext
 * @param string $key
 * @param string $nonce
 * @param string $aad
 * @return string
 * @throws Error
 */
function aes_xgcm_encrypt(string $plaintext, string $key, string $nonce, string $aad = ''): string
{
    if (\mb_strlen($key, '8bit') !== 32) {
        throw new Error('Key must be 32 bytes');
    }
    if (\mb_strlen($nonce, '8bit') !== 44) {
        throw new Error('Nonce must be 44 bytes');
    }

    $subKey = \hash_hmac('sha256', $key, \mb_substr($nonce, 0, 32, '8bit'));
    $nonce = \mb_substr($nonce, 32, 12, '8bit');

    $tag = '';
    $cipher = \openssl_encrypt(
        $plaintext,
        'aes-256-gcm',
        $subKey,
        OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
        $nonce,
        $tag,
        $aad,
        16
    );
    return $tag . $cipher;
}

/**
 * @param string $plaintext (Optional)
 * @return string
 */
function aes_xgcm_generate_nonce($plaintext = '')
{
    // Optional: feed a HMAC of the plaintext under a random key to the kernel's CSPRNG
    if (!empty($plaintext)) {
        \file_put_contents(
            '/dev/random',
            \hash_hmac('sha512', $plaintext, \random_bytes(64), true)
        );
    }
    return \random_bytes(44);
}
