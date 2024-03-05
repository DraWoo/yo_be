package com.yo.sm.config;

import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Component
public class JwtTokenProvider {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration-ms}")
    private int jwtExpirationInMs;

    /**
     * JWT 토큰 생성
     * @param username 인증에 사용되는 사용자의 이름.
     * 이 메소드는 username 매개변수를 직접 setSubject 메서드에 전달. 이는 JWT 토큰의 "sub" (subject) 클레임을 설정하는데 사용
     * @return 생성된 JWT 토큰 문자열.
     */
    public String generateToken(String username) {
        // 현재 시간 호출
        Date now = new Date();
        //토큰 만료 날짜 설정 = 현재 시간 + 토큰 만료시간
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);

        return Jwts.builder()
                .setSubject(username)   //수신자 설정 => 보통 사용자ID, 이메밀
                .setIssuedAt(now)       //토큰이 발행된 시간설정
                .setExpiration(expiryDate)//토큰이 만료될 시간설정
                .signWith(SignatureAlgorithm.HS512, jwtSecret) //토큰을 서명하는데 사용될 알고리즘과 키를 설정
                .compact(); //생성된 jwt를 집약화하고 문자열로 변환
    }


    // JWT 토큰에서 인증 정보 조회
    public String getUsernameFromJWT(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    // JWT 토큰의 유효성 검증
    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException | MalformedJwtException | ExpiredJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            // 로그 출력 또는 예외 처리. 예외에 대한 정보를 출력해야함.
            System.out.println("Error validating JWT token: " + e.getMessage());
            return false;
        }
    }

    public String resolveToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
    /**
     * JWT 토큰 갱신 메서드
     * 주어진 토큰의 사용자 정보를 가져와서 새로운 토큰을 생성합니다.
     *
     * @param token 갱신할 JWT 토큰
     * @return 새로운 JWT 토큰
     * 1초 = 1000 밀리초
     * 1분 = 60초 = 60 * 1000 밀리초
     * 1시간 = 60분 = 60 * 60 * 1000 밀리초
     * 1일 = 24시간 = 24 * 60 * 60 * 1000 밀리초
     * 30일 = 30 * 24 * 60 * 60 * 1000 밀리초 = 2592000000 밀리초
     */
    public String generateRefreshToken(String username) {
        long refreshTokenDurationMs = 2592000000L; // 예를 들어 30일
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshTokenDurationMs);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    /**
     * JWT 토큰으로부터 인증 정보를 얻는 메서드
     * JWT 토큰의 사용자 정보를 이용해서 인증 객체(Authentication)를 생성합니다.
     *
     * @param token 사용자 정보가 담긴 JWT 토큰
     * @return 생성된 Authentication 객체
     */
    public Authentication getAuthentication(String token) {
        String username = getUsernameFromJWT(token);
        return new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
    }

    private List<String> blackList = new ArrayList<>();

    // 토큰 무효화 로직
    public void invalidateToken(String token) {
        blackList.add(token);
    }
}