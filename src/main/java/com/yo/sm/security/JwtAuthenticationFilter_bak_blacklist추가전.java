package com.yo.sm.security;

import com.yo.sm.config.JwtTokenProvider;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

/**
 * JWT 인증 필터 클래스입니다.
 * 이 필터는 HTTP 요청의 헤더에서 JWT를 추출하고, token을 검증하여 사용자의 인증 상태를 설정합니다.
 * Spring Security의 필터 체인에 통합되어, 보안이 요구되는 요청에 대해 사용자 인증을 수행합니다.
 * #주요 기능은 다음과 같습니다:
 * - 요청 헤더에서 JWT 추출: HTTP 요청에서 'Authorization' 헤더를 찾고, Bearer 토큰을 추출합니다.
 * - 토큰 검증: JwtTokenProvider를 사용하여 토큰의 유효성을 검사합니다. 토큰이 유효하면 사용자 인증 정보를 SecurityContext에 설정합니다.
 * - 사용자 인증 정보 설정: 토큰이 유효한 경우, 사용자의 인증 정보(주로 사용자 이름)를 바탕으로 UsernamePasswordAuthenticationToken을 생성하고,
 *   이를 SecurityContext에 저장합니다.
 * 이 필터는 OncePerRequestFilter를 상속받아, 요청당 한 번씩 실행됩니다.
 * 요청이 서버에 도달하기 전에 실행되어, 보안이 필요한 요청에 대해 사용자가 적절히 인증되었는지를 보장합니다.
 * 만약 토큰이 만료되었거나 유효하지 않은 경우, 적절한 HTTP 응답 상태(401 Unauthorized)와 메시지를 반환하여 클라이언트에게 알립니다.
 */

@Component
@Slf4j
public class JwtAuthenticationFilter_bak_blacklist추가전 extends OncePerRequestFilter {

    @Resource
    private JwtTokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws IOException, ServletException {

        try {
            String jwt = getJwtFromRequest(request);

            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                String username = tokenProvider.getUsernameFromJWT(jwt);

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("[인증 성공] 사용자: {}", username);
            }
        } catch (ExpiredJwtException e) {
            //log.info("[인증 실패] JWT 만료됨: {}", e.getMessage());
        } catch (Exception e) {
            log.error("[인증 오류] 보안 컨텍스트 설정 실패", e);
        }
        filterChain.doFilter(request, response);
    }

    /**
     * HTTP 요청의 헤더에서 JWT를 추출합니다.
     *
     * @param request HTTP 요청 객체
     * @return 추출된 JWT 문자열, 없으면 null
     */
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}