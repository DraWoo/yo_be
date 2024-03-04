package com.yo.sm.config;

import java.security.SecureRandom;
import java.util.Base64;

public class JWTSecurityKeyGenerator {
    public static void main(String[] args) {
        //암호학적으로 강력한 난수를 생성 인스턴스 =>SecureRandom
        SecureRandom random = new SecureRandom();

        // 난수를 저장할 바이트 배열을 생성합니다. JWT 비밀키로 사용될 64바이트 크기의 배열을 생성합니다.
        // 이 크기는 암호화에 사용되는 키의 강도를 결정합니다. 64바이트는 512비트에 해당하며
        // HS512 알고리즘을 사용할 때 적절한 크기입니다.
        byte[] bytes = new byte[64];
        random.nextBytes((bytes));

        // 바이트 배열을 Base64 인코딩으로 변환합니다. 이는 배열을 문자열로 변환하고,
        // 특수 문자가 없는 형태로 만들어 JWT 비밀키로 사용할 수 있도록 합니다.
        // Base64 인코딩은 바이너리 데이터를 텍스트 형식으로 안전하게 인코딩하고 전송하는 데 사용됩니다.
        String secretKey = Base64.getEncoder().encodeToString(bytes);
        System.out.println("JWT Secret Key: " + secretKey);
    }
}
