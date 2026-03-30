<?php
/**
 * crypto.php
 *
 * Cryptographic utility functions for encrypting and decrypting data.
 * Provides symmetric encryption (AES-256-CBC) and asymmetric encryption (RSA).
 *
 * SECURITY NOTES:
 * - Uses AES-256-CBC for symmetric encryption with random IVs
 * - Uses RSA with AES-256-CBC for asymmetric encryption (openssl_seal/open)
 * - All encryption operations should be treated as critical security functions
 * - Failed decryption attempts are logged for security monitoring
 *
 * ResearchChatAI
 * Author: Marc Becker, David de Jong
 * License: MIT
 */

// =============================================================================
// CONSTANTS
// =============================================================================

define('CRYPTO_AES_IV_LENGTH', 16);
define('CRYPTO_MIN_CIPHERTEXT_LENGTH', 17); // IV + at least 1 byte
define('CRYPTO_KEY_LENGTH', 32); // 256 bits
define('CRYPTO_CIPHER_METHOD', 'AES-256-CBC');

// =============================================================================
// ENCRYPTION KEY MANAGEMENT
// =============================================================================

/**
 * Get encryption key from environment
 *
 * Retrieves the encryption key used for symmetric encryption from environment
 * variables. Validates key format and length.
 *
 * @return string Encryption key or empty string if not configured
 */
function getEncryptionKey(): string
{
    global $env;
    
    // Try to get key from $env array first, then environment variable
    $key = $env['ENCRYPTION_KEY'] ?? getenv('ENCRYPTION_KEY');
    
    if ($key === false || $key === '') {
        return '';
    }
    
    // Validate key length (should be 32 bytes for AES-256)
    // Log warning but remain backward compatible with existing deployments
    if (strlen($key) !== CRYPTO_KEY_LENGTH) {
        error_log("WARNING: ENCRYPTION_KEY has invalid length. Expected " . CRYPTO_KEY_LENGTH . " bytes, got " . strlen($key) . ". Consider regenerating with a proper 256-bit key.");
    }
    
    return $key;
}

// =============================================================================
// SYMMETRIC ENCRYPTION (AES-256-CBC)
// =============================================================================

/**
 * Encrypt string using AES-256-CBC
 *
 * Encrypts plaintext using AES-256-CBC with a random IV. The IV is prepended
 * to the ciphertext and the result is base64-encoded.
 *
 * @param string $plaintext Data to encrypt
 * @return string Base64-encoded IV + ciphertext, or plaintext if encryption fails
 */
function encryptString(string $plaintext): string
{
    // Get encryption key
    $key = getEncryptionKey();
    
    // If no key configured, return plaintext (backward compatibility)
    if ($key === '') {
        error_log("WARNING: Encryption attempted but ENCRYPTION_KEY not configured");
        return $plaintext;
    }
    
    // Validate input
    if ($plaintext === '') {
        return '';
    }
    
    try {
        // Generate random IV
        $iv = random_bytes(CRYPTO_AES_IV_LENGTH);
        
        // Encrypt data
        $ciphertext = openssl_encrypt(
            $plaintext,
            CRYPTO_CIPHER_METHOD,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        if ($ciphertext === false) {
            $error = openssl_error_string();
            error_log("ERROR: Encryption failed: " . ($error ?: 'Unknown error'));
            return $plaintext; // Return plaintext on failure for backward compatibility
        }
        
        // Prepend IV to ciphertext and encode
        return base64_encode($iv . $ciphertext);
        
    } catch (Exception $e) {
        error_log("ERROR: Exception during encryption: " . $e->getMessage());
        return $plaintext; // Return plaintext on failure for backward compatibility
    }
}

/**
 * Decrypt string using AES-256-CBC
 *
 * Decrypts ciphertext that was encrypted with encryptString(). Expects
 * base64-encoded IV + ciphertext.
 *
 * @param string $ciphertext Base64-encoded IV + ciphertext
 * @return string Decrypted plaintext, or original input if not encrypted/invalid
 */
function decryptString(string $ciphertext): string
{
    // Get encryption key
    $key = getEncryptionKey();
    
    // If no key configured, return ciphertext as-is
    if ($key === '') {
        return $ciphertext;
    }
    
    // Validate input
    if ($ciphertext === '') {
        return '';
    }
    
    try {
        // Decode base64
        $data = base64_decode($ciphertext, true);
        
        // Validate decoded data
        if ($data === false || strlen($data) < CRYPTO_MIN_CIPHERTEXT_LENGTH) {
            // Not encrypted or invalid format - return as-is
            return $ciphertext;
        }
        
        // Extract IV and ciphertext
        $iv = substr($data, 0, CRYPTO_AES_IV_LENGTH);
        $encrypted = substr($data, CRYPTO_AES_IV_LENGTH);
        
        // Decrypt
        $plaintext = openssl_decrypt(
            $encrypted,
            CRYPTO_CIPHER_METHOD,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        // Return decrypted data or original if decryption failed
        if ($plaintext === false) {
            error_log("WARNING: Decryption failed for data. Returning original ciphertext.");
            return $ciphertext;
        }
        
        return $plaintext;
        
    } catch (Exception $e) {
        error_log("Decryption error: " . $e->getMessage());
        return $ciphertext;
    }
}

// =============================================================================
// ASYMMETRIC ENCRYPTION (RSA + AES-256-CBC)
// =============================================================================

/**
 * Encrypt message with RSA public key
 *
 * Uses hybrid encryption (RSA + AES-256-CBC) via openssl_seal. The envelope key,
 * IV, and encrypted data are returned as base64-encoded components separated by ':'.
 *
 * Format: base64(envelopeKey):base64(iv):base64(sealedData)
 *
 * @param string $plaintext Message to encrypt
 * @param string $publicKey PEM-formatted RSA public key
 * @return string Encrypted message or empty string on failure
 */
function encryptMessageWithPublicKey(string $plaintext, string $publicKey): string
{
    // Don't encrypt empty strings
    if ($plaintext === '') {
        return '';
    }
    
    // Validate public key
    if (empty($publicKey)) {
        error_log("ERROR: Public key is empty in encryptMessageWithPublicKey");
        return $plaintext;
    }
    
    try {
        $sealedData = '';
        $envelopeKeys = [];
        $iv = '';
        
        // Perform hybrid encryption
        $result = openssl_seal(
            $plaintext,
            $sealedData,
            $envelopeKeys,
            [$publicKey],
            CRYPTO_CIPHER_METHOD,
            $iv
        );
        
        if (!$result) {
            $error = openssl_error_string();
            error_log("ERROR: openssl_seal failed: " . ($error ?: 'Unknown error'));
            return $plaintext;
        }
        
        // Verify we got the expected results
        if (empty($envelopeKeys) || empty($iv) || empty($sealedData)) {
            error_log("ERROR: openssl_seal produced incomplete results");
            return $plaintext;
        }
        
        // Return envelope key, IV, and sealed data as base64-encoded components
        return base64_encode($envelopeKeys[0]) . ':' . 
               base64_encode($iv) . ':' . 
               base64_encode($sealedData);
               
    } catch (Exception $e) {
        error_log("ERROR: Exception in encryptMessageWithPublicKey: " . $e->getMessage());
        return $plaintext;
    }
}

/**
 * Decrypt message with RSA private key
 *
 * Decrypts messages encrypted with encryptMessageWithPublicKey. Expects format:
 * base64(envelopeKey):base64(iv):base64(sealedData)
 *
 * @param string $ciphertext Encrypted message in expected format
 * @param string|null $privateKey PEM-formatted RSA private key
 * @return string Decrypted message or original ciphertext if decryption fails
 */
function decryptMessageWithPrivateKey(string $ciphertext, ?string $privateKey): string
{
    // If no private key provided, return ciphertext as-is
    if ($privateKey === null || $privateKey === '') {
        error_log("WARNING: Decryption attempted without private key");
        return $ciphertext;
    }
    
    // Handle empty ciphertext
    if ($ciphertext === '') {
        return '';
    }
    
    try {
        // Server-side format (from openssl_seal): base64(envelopeKey):base64(iv):base64(sealedData)
        $parts = explode(':', $ciphertext, 3);

        if (count($parts) !== 3) {
            error_log("WARNING: Invalid ciphertext format - expected 3 parts, got " . count($parts));
            return $ciphertext;
        }

        list($envelopeKeyB64, $ivB64, $sealedDataB64) = $parts;

        // Decode base64 components
        $envelopeKey = base64_decode($envelopeKeyB64, true);
        $iv = base64_decode($ivB64, true);
        $sealedData = base64_decode($sealedDataB64, true);

        // Validate decoded data
        if ($envelopeKey === false || $iv === false || $sealedData === false) {
            error_log("WARNING: Invalid base64 encoding in ciphertext components");
            return $ciphertext;
        }

        // Validate IV length
        if (strlen($iv) !== CRYPTO_AES_IV_LENGTH) {
            error_log("WARNING: Invalid IV length: " . strlen($iv) . " (expected " . CRYPTO_AES_IV_LENGTH . ")");
            return $ciphertext;
        }

        // Decrypt using private key
        $plaintext = '';
        $result = openssl_open(
            $sealedData,
            $plaintext,
            $envelopeKey,
            $privateKey,
            CRYPTO_CIPHER_METHOD,
            $iv
        );

        if (!$result) {
            $error = openssl_error_string();
            error_log("WARNING: openssl_open failed: " . ($error ?: 'Unknown error'));
            return $ciphertext;
        }

        return $plaintext;
        
    } catch (Exception $e) {
        error_log("ERROR: Exception in decryptMessageWithPrivateKey: " . $e->getMessage());
        return $ciphertext;
    }
}

// =============================================================================
// SECURE MEMORY CLEANUP
// =============================================================================

/**
 * Securely clear sensitive data from memory
 *
 * Overwrites sensitive string data to prevent it from lingering in memory.
 * Use for encryption keys, passwords, and other sensitive data.
 *
 * @param string &$data String to clear (passed by reference)
 */
function secureClearString(string &$data): void
{
    if (function_exists('sodium_memzero')) {
        sodium_memzero($data);
    } else {
        // Fallback: overwrite with random data then empty string
        $length = strlen($data);
        if ($length > 0) {
            try {
                $data = random_bytes($length);
            } catch (Exception $e) {
                $data = str_repeat("\0", $length);
            }
            $data = '';
        }
    }
}