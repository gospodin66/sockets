<?php
class Openssl_EncryptDecrypt {

    private const CYPHER     = 'AES-256-CBC';
    private const OPTIONS    = OPENSSL_RAW_DATA;
    private const HASH_ALGO  = 'sha256';
    private const SHA2LEN    = 32;

    public function encrypt_cbc ($pure_string, $encryption_key) {
        try {
            $ivlen          = openssl_cipher_iv_length(self::CYPHER);
            $iv             = openssl_random_pseudo_bytes($ivlen);
            $ciphertext_raw = openssl_encrypt($pure_string, self::CYPHER, $encryption_key, self::OPTIONS, $iv);
            $hmac = hash_hmac(self::HASH_ALGO, $ciphertext_raw, $encryption_key, true);
    
            return base64_encode($iv.$hmac.$ciphertext_raw);
        } catch (\Exception $e){
            throw $e;
        }

        echo '!! not supposed to be here !!';
        return;
    }

    public function decrypt_cbc ($encrypted_string, $encryption_key) {
        $encrypted_string = base64_decode($encrypted_string);

        if(! $encrypted_string || empty($encrypted_string)){
            return null;
        }
        try {
            $ivlen              = openssl_cipher_iv_length(self::CYPHER);
            $iv                 = substr($encrypted_string, 0, $ivlen);
            $hmac               = substr($encrypted_string, $ivlen, self::SHA2LEN);
            $ciphertext_raw     = substr($encrypted_string, ($ivlen+self::SHA2LEN));
            $original_plaintext = openssl_decrypt($ciphertext_raw, self::CYPHER, $encryption_key, self::OPTIONS, $iv);
            
            $calcmac = hash_hmac(self::HASH_ALGO, $ciphertext_raw, $encryption_key, true);
    
            if(function_exists('hash_equals')) {
                if (hash_equals($hmac, $calcmac)){
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

        echo '!! not supposed to be here !!';
        return;
    }


    /**
     * (Optional)
     * hash_equals() function polyfilling.
     * PHP 5.6+ timing attack safe comparison
     */
    private function hash_equals_custom($knownString, $userString) {
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
        return (0 === $result);
    }
}
?>