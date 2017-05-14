<?php

use PHPUnit\Framework\TestCase;

class BasicTest extends TestCase
{
    public function testEncryptDecrypt()
    {
        $key = random_bytes(32);
        $message = 'This is a secret';
        $nonce = aes_xgcm_generate_nonce($message);

        $ciphertext = aes_xgcm_encrypt($message, $key, $nonce);
        $this->assertSame(
            aes_xgcm_decrypt($ciphertext, $key, $nonce),
            $message,
            'Decryption error'
        );
    }
}
