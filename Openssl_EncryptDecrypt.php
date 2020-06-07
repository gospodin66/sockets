<?php
define('CYPHER', 'AES-256-CBC');
define('OPTIONS', OPENSSL_RAW_DATA);
define('HASH_ALGO', 'sha256');
define('SHA2LEN', 32);
class Openssl_EncryptDecrypt {

    public function encrypt ($pure_string, $encryption_key) {

        try {
            $ivlen          = openssl_cipher_iv_length(CYPHER);
            $iv             = openssl_random_pseudo_bytes($ivlen);
            $ciphertext_raw = openssl_encrypt($pure_string, CYPHER, $encryption_key, OPTIONS, $iv);
            $hmac = hash_hmac(HASH_ALGO, $ciphertext_raw, $encryption_key, true);
    
            return base64_encode($iv.$hmac.$ciphertext_raw);
        } catch (\Exception $e){
            throw $e;
        }
    }

    public function decrypt ($encrypted_string, $encryption_key) {
        $encrypted_string = base64_decode($encrypted_string);

        if(! $encrypted_string){
            return null;
        }

        try {
            $ivlen              = openssl_cipher_iv_length(CYPHER);
            $iv                 = substr($encrypted_string, 0, $ivlen);
            $hmac               = substr($encrypted_string, $ivlen, SHA2LEN);
            $ciphertext_raw     = substr($encrypted_string, ($ivlen+SHA2LEN));
            $original_plaintext = @openssl_decrypt($ciphertext_raw, CYPHER, $encryption_key, OPTIONS, $iv);
            
            $calcmac = hash_hmac(HASH_ALGO, $ciphertext_raw, $encryption_key, true);
    
            if(function_exists('hash_equals')) {
                if (@hash_equals($hmac, $calcmac)){
                    return $original_plaintext;
                }
            } else {
                if ($this->hash_equals_custom($hmac, $calcmac)){
                    return $original_plaintext;
                }
            }
        } catch (\Exception $e){
            throw $e;
        }
    }
    /**
     * (Optional)
     * hash_equals() function polyfilling.
     * PHP 5.6+ timing attack safe comparison
     */
    function hash_equals_custom($knownString, $userString) {
        if (function_exists('mb_strlen')) {
            $kLen = mb_strlen($knownString, '8bit');
            $uLen = mb_strlen($userString, '8bit');
        } else {
            $kLen = strlen($knownString);
            $uLen = strlen($userString);
        }
        if ($kLen !== $uLen) {
            return false;
        }
        $result = 0;
        for ($i = 0; $i < $kLen; $i++) {
            $result |= (ord($knownString[$i]) ^ ord($userString[$i]));
        }
        return 0 === $result;
    }
}
?>