package com.yo.sm.security;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JwtAuthenticationFailureHandler는 인증 과정에서 실패(예: 잘못된 토큰, 토큰 누락 등)가 발생했을 때
 * 클라이언트에게 적절한 HTTP 응답을 보내는 역할을 합니다. 이 클래스는 AuthenticationEntryPoint 인터페이스를 구현합니다.
 *
 * SecurityConfig 클래스에서 이 핸들러를 사용하여 인증 실패 시의 처리 로직을 정의합니다.
 */
@Component
public class JwtAuthenticationFailureHandler implements AuthenticationEntryPoint {

    /**
     * commence 메서드는 인증 과정에서 예외가 발생했을 때 호출됩니다.
     * 이 메서드는 HTTP 응답으로 401 Unauthorized 에러와 함께 오류 메시지를 클라이언트에게 전송합니다.
     *
     * @param request HTTP 요청 정보를 담고 있는 HttpServletRequest 객체
     * @param response HTTP 응답 정보를 담고 있는 HttpServletResponse 객체
     * @param authException 인증 과정에서 발생한 예외
     * @throws IOException 입출력 예외 처리
     */
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        // 인증 실패 시 클라이언트에게 보낼 응답을 구현
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: Authentication token was either missing or invalid.");
    }
}
