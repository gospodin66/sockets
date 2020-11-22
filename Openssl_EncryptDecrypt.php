<?php
class Openssl_EncryptDecrypt {
    private const CYPHER     = 'AES-256-CBC';
    private const OPTIONS    = OPENSSL_RAW_DATA;
    private const HASH_ALGO  = 'sha256';
    private const HASH_LEN   = 32;

    public function fetch_key(){
        try {
            if(file_exists('.env') === false){
                echo "crypto-key not found.\n";
                return false;
            } else { 
                if(($key = file_get_contents(".env")) === false){
                    echo 'error reading crypto-key.';
                    return false;
                }
            }
        } catch(\Throwable $e) {
            throw $e;
            return false;
        }
        return base64_decode($key);
    }
    public function encrypt_cbc($clrtext){
        if(($base64key = self::fetch_key()) === null){
            return false;
        }
        $key = base64_decode($base64key);
        try {
            $ivlen      = openssl_cipher_iv_length(self::CYPHER);
            $iv         = openssl_random_pseudo_bytes($ivlen);
            $ciphertext = openssl_encrypt($clrtext, self::CYPHER, $key, self::OPTIONS, $iv);
            $hmac       = hash_hmac(self::HASH_ALGO, $iv.$ciphertext, $key, true);
            return base64_encode($iv.$hmac.$ciphertext);
        } catch (\Exception $e){
            throw $e;
            return false;
        }
        return false;
    }
    public function decrypt_cbc($encrypted){
        if(($base64key = self::fetch_key()) === null){
            return false;
        }
        if($encrypted === false || empty($encrypted)){
            return false;
        }
        $key = base64_decode($base64key);
        $encrypted = base64_decode($encrypted);
        try {
            $ivlen      = openssl_cipher_iv_length(self::CYPHER);
            $iv         = substr($encrypted, 0, $ivlen);
            $hmac       = substr($encrypted, $ivlen, self::HASH_LEN);
            $ciphertext = substr($encrypted, ($ivlen+self::HASH_LEN));
            $clrtext    = openssl_decrypt($ciphertext, self::CYPHER, $key, self::OPTIONS, $iv);
            
            if($clrtext === false){
                return false;
            }
            $calcmac = hash_hmac(self::HASH_ALGO, $iv.$ciphertext, $key, true);
            if(function_exists('hash_equals')) {
                if (hash_equals($hmac, $calcmac)){ return $clrtext; }
            } else {
                if ($this->hash_equals_custom($hmac, $calcmac)){ return $clrtext; }
            }
            return false;
        } catch (\Exception $e){
            throw $e;
            return false;
        }
        return false;
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