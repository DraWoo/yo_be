package com.yo.sm.config;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
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
import java.util.concurrent.ConcurrentHashMap;

/**
 * JWT 토큰 관리를 위한 핵심 클래스
 * 이 클래스는 JSON Web Token(JWT)의 생명주기를 관리하는 여러 메소드를 제공
 * 주요 기능은 다음과 같습니다:
 * - JWT 토큰 생성: 사용자의 인증 정보를 바탕으로 JWT 토큰을 생성합니다. 토큰에는 사용자 식별 정보 및 토큰의 유효기간이 포함됩니다.
 * - JWT 토큰 검증: 제공된 토큰이 유효한지 검증합니다. 토큰의 서명, 만료일, 구조의 유효성을 검사합니다.
 * - JWT 토큰 갱신: 만료된 토큰에 대해 새로운 토큰을 발급합니다. 이 기능은 사용자의 세션이 만료되었을 때, 자동으로 새 세션을 생성하여 사용자 경험을 개선합니다.
 * - JWT 토큰 무효화: 로그아웃 또는 사용자 권한 변경 시 사용되며, 특정 토큰을 더 이상 유효하지 않도록 설정합니다.
 * {@code validateToken} 메소드는 토큰의 유효성을 검증하며, 만료된 토큰이 전달되면 {@link ExpiredJwtException}을 발생시킵니다.
 * {@code resolveToken} 메소드는 HTTP 요청의 헤더에서 토큰을 추출하며, 필요한 경우 이를 갱신하거나 무효화할 수 있습니다.
 * 이 클래스는 Spring Security와 함께 작동하여, 시스템 전반에 걸쳐 안전한 인증 메커니즘을 제공합니다.
 */
@Component
@Slf4j
public class JwtTokenProvider {

    // JWT 토큰을 암호화하기 위한 비밀 키.
    // 이 값은 Spring의 Value 어노테이션을 사용하여 application.yml 파일에서 주입받는다.
    @Value("${app.jwt.secret}")
    private String jwtSecret;

    // JWT 토큰에 만료시간
    @Value("${app.jwt.expiration-sec}")
    private int jwtExpirationInSec;

    /**
     *사용자 이름과 만료 시간을 기반으로 JWT 토큰을 생성
     * @param username 사용자 이름
     * @param durationMs 토큰의 유효 기간 (밀리초 단위)
     * @return 생성된 JWT 토큰 문자열
     */
    private String generateTokenWithExpiry(String username, long durationMs) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + durationMs);

        log.info("[JWT 생성] 사용자: {}, 만료 시간: {}", username, expiryDate);
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    /**
     * 사용자 이름을 받아 JWT 토큰을 생성합니다. 토큰의 만료 시간은 설정 파일에서 정의된 값을 사용합니다.
     *
     * @param username 사용자의 이름
     * @return 생성된 JWT 토큰 문자열
     */
    public String generateToken(String username) {
        int jwtExpirationInMillis = jwtExpirationInSec * 1000;
        String token = generateTokenWithExpiry(username, jwtExpirationInMillis);
        log.info("[JWT 생선] 사용자: {}", username);
        return token;
    }

    /**
     * JWT 토큰으로부터 사용자 이름을 추출합니다.
     *
     * @param token JWT 토큰
     * @return 추출된 사용자 이름
     */
    public String getUsernameFromJWT(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();

        return claims.getSubject();
    }

    /**
     * 제공된 JWT 토큰이 유효한지 검증합니다.
     *
     * @param authToken 검증할 JWT 토큰
     * @return 토큰이 유효하면 true, 그렇지 않으면 false
     */
    public boolean validateToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (ExpiredJwtException e) {
            log.error("[JWT 검증] 만료된 JWT: {}. 현재 시간: {}, 차이: {} 밀리초. 허용 시간 오차: 0 밀리초.",
                    e.getClaims().getExpiration(), new Date(), Math.abs(new Date().getTime() - e.getClaims().getExpiration().getTime()));
            throw e;
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException ex) {
            // 이 예외들은 여기에서 로그를 남기고 false를 반환합니다.
            log.error("[JWT 검증 실패] 이유: {}", ex.getMessage());
            return false;
        }
    }

    /**
     * HTTP 요청에서 JWT 토큰을 추출합니다.
     *
     * @param request HTTP 요청 객체
     * @return 추출된 토큰 문자열, 없으면 null
     */
    public String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // "Bearer " 다음 부분을 추출하여 토큰 반환
        }
        return null; // 토큰이 없거나 형식이 맞지 않는 경우 null 반환
    }
    /**
     * JWT 토큰 갱신 메서드
     * 주어진 토큰의 사용자 정보를 가져와서 새로운 토큰을 생성합니다.
     *
     * @param:token 갱신할 JWT 토큰
     * @return 새로운 JWT 토큰
     * 1초 = 1000 밀리초
     * 1분 = 60초 = 60 * 1000 밀리초
     * 1시간 = 60분 = 60 * 60 * 1000 밀리초
     * 1일 = 24시간 = 24 * 60 * 60 * 1000 밀리초
     * 30일 = 30 * 24 * 60 * 60 * 1000 밀리초 = 2592000000 밀리초
     */
    public String generateRefreshToken(String username) {
        long refreshTokenDurationMs = 2592000000L; // 30일
        String newToken = generateTokenWithExpiry(username,refreshTokenDurationMs);
        log.info("[JWT 갱신] 사용자: {}, 새로운 토큰 발행", username);
        return newToken;
    }

    /**
     * JWT 토큰으로부터 인증 정보를 생성합니다.
     *
     * @param token JWT 토큰
     * @return 인증 객체 (Authentication)
     */
    public Authentication getAuthentication(String token) {
        String username = getUsernameFromJWT(token);
        // 해당 사용자에 대한 권한 정보는 없으므로, 빈 권한 목록으로 인증 토큰을 생성합니다.
        return new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
    }

    // 실제 환경에서는 레디스나 데이터베이스를 사용할 수 있습니다.
    // 여기서는 예시로 ConcurrentHashMap을 사용합니다.
    private ConcurrentHashMap<String, Boolean> blackList = new ConcurrentHashMap<>();
    /**
     * 특정 JWT 토큰을 무효화합니다.
     *
     * @param token 무효화할 JWT 토큰
     */
    public void invalidateToken(String token) {
        // 블랙리스트에 토큰을 추가하여 무효화합니다.
        blackList.put(token, Boolean.TRUE);
        log.info("[JWT 무효화] 토큰이 블랙리스트에 추가되었습니다: {}", token);
    }

    /**
     * 주어진 토큰이 무효화되었는지 확인합니다.
     *
     * @param token 검증할 JWT 토큰
     * @return 토큰이 무효화되었다면 true, 그렇지 않다면 false
     */
    public boolean isTokenInvalidated(String token) {
        return blackList.getOrDefault(token, Boolean.FALSE);
    }
}