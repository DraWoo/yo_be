package com.yo.sm.config;

import java.security.SecureRandom;
import java.util.Base64;

public class SecretKeyGenerator {
    public static void main(String[] args) {
        SecureRandom secureRandom = new SecureRandom(); // SecureRandom is a good choice for generating random bytes
        byte[] key  = new byte[64]; // 512-bit key
        secureRandom.nextBytes(key );
        String secretKey = Base64.getEncoder().encodeToString(key);
        System.out.println("Generate secret key is: " + secretKey);
    }
}