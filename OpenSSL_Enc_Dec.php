<?php
class OpenSSL_Enc_Dec {
    
    private const CYPHER = 'AES-256-CBC';
    private const OPTIONS = OPENSSL_RAW_DATA;
    private const HASH_ALGO = 'sha256';
    private const HASH_LEN = 32;
    private const PRIVATE_KEY_LENGTH = 4096;
    private const CRYPTO_HASH_ALGO_256 = 'sha256';
    private const CRYPTO_HASH_ALGO_512 = 'sha512';

    public function fetch_key() {
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
        return $key;
        //return (password_verify($key, $hash) ? base64_decode($key) : false);
    }

    public function generate_keypair($user = 'master', $_token) {
        $keys_dir     = "./keys";
        $private_path = "$keys_dir/$user/private.pem";
        $public_path  = "$keys_dir/$user/public.pem";
        
        $privateKeyString = file_exists($private_path) ? file_get_contents($private_path) : null;
        $publicKeyString  = file_exists($public_path)  ? file_get_contents($public_path)  : null;
        
        // generate keypair if !exists
        if(empty($privateKeyString) || empty($publicKeyString))
        {
            $keyPair = openssl_pkey_new([
                "digest_alg" => self::CRYPTO_HASH_ALGO_512,
                "private_key_bits" => self::PRIVATE_KEY_LENGTH,
                "private_key_type" => OPENSSL_KEYTYPE_RSA
            ]);
            
            openssl_pkey_export($keyPair, $privateKeyString);
            
            $keyDetails      = openssl_pkey_get_details($keyPair);
            $publicKeyString = $keyDetails["key"];
            
            if(!file_exists("$keys_dir/$user")){
                if(!mkdir("$keys_dir/$user", 0755, true)){
                    echo "mkdir() user-dir error.";
                    return false;
                }
            }
            
            if(file_put_contents($private_path, $privateKeyString) === false
             || file_put_contents($public_path, $publicKeyString) === false)
            {
                echo "Keypair store error.";
                return false;
            }
        }
        return password_hash($_token, PASSWORD_BCRYPT, ['cost' => 10]);
    }

    public function get_keypair($user = 'master', $_token) {
        $keys_dir     = "./keys";
        $private_path = "$keys_dir/$user/private.pem";
        $public_path  = "$keys_dir/$user/public.pem";
        
        $privateKeyString = file_exists($private_path) ? trim(file_get_contents($private_path)) : null;
        $publicKeyString  = file_exists($public_path)  ? trim(file_get_contents($public_path))  : null;

        if(empty($privateKeyString) || empty($publicKeyString)) { return false; }

        if(false === ($publicKey = openssl_pkey_get_public([$publicKeyString, $_token]))) {
            echo "Malformed public key.\n";
            return false;
        }
        if(false === ($privateKey = openssl_pkey_get_private([$privateKeyString, $_token]))) {
            echo "Malformed private key.\n";
            return false;
        }

        return ['public' => $publicKey, 'private' => $privateKey];
    }

    public function get_keypair_strings($user = 'master') {
        $keys_dir     = "./keys";
        $private_path = "$keys_dir/$user/private.pem";
        $public_path  = "$keys_dir/$user/public.pem";
        
        $privateKeyString = file_exists($private_path) ? trim(file_get_contents($private_path)) : null;
        $publicKeyString  = file_exists($public_path)  ? trim(file_get_contents($public_path))  : null;

        if(empty($privateKeyString) || empty($publicKeyString)) { return false; }

        return ['public' => $publicKeyString, 'private' => $privateKeyString];
    }

    /**
     * 
     * @param _token => passphrase for encryption
     * @param data   => data to encrypt
     * 
     * @return string
     */
    public function encryptRSA($_token, $data, $keytype = 'public') : string {

        if(false === ($keypair = self::get_keypair('master', $_token))){
            echo "Error fetching RSA key.\n";
            return false;
        }

        if($keytype === 'public'){
            if(false === openssl_public_encrypt($data, $encryptedWithPublic, $keypair['public'])) {
                echo "Error encrypting with public key.\n";
                return false;
            }
            openssl_free_key($keypair['public']);
        } else if($keytype === 'private'){
            if(false === openssl_private_encrypt($data, $encryptedWithPrivate, $keypair['private'])) {
                echo "Error encrypting with private key.\n";
                return false;
            }
            openssl_free_key($keypair['private']);
        } else {
            echo "invalid key type.\n";
        }

        unset($data);

        return (($keytype === 'public')
                ? base64_encode($encryptedWithPublic)
                : (($keytype === 'private')
                ? base64_encode($encryptedWithPrivate)
                : false)); 
    }

    /**
     * 
     * @param _token => passphrase for encryption
     * @param data   => data to encrypt
     * 
     * @return string
     */
    public function decryptRSA($_token, $encryptedb64, $keytype = 'public') : string {

        if(false === ($keypair = self::get_keypair('master', $_token))){
            echo "Error fetching RSA key.\n";
            return false;
        }
        
        $encrypted = base64_decode($encryptedb64);

        if($keytype === 'public'){
            if(false === openssl_public_decrypt($encrypted, $decrtypted, $keypair['public'])) {
                echo "error decrypting with public key what was encrypted with private key\n";
                return false;
            }
            openssl_free_key($keypair['public']);
        } else if($keytype === 'private'){
            if(false === openssl_private_decrypt($encrypted, $decrtypted, $keypair['private'])) {
                echo "error decrypting with private key what was encrypted with public key\n";
                return false;
            }
            openssl_free_key($keypair['private']);
        } else {
            echo "invalid key type.\n";
        }
        

        return $decrtypted;
    }


    public function encrypt_cbc($clrtext, $key = null){
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
        } catch (\Throwable $e){
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
        } catch (\Throwable $e){
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