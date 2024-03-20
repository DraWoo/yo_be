package com.yo.sm.config;

import com.yo.sm.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.annotation.Resource;

@EnableWebSecurity // Spring Security 설정을 활성화합니다.
public class SecurityConfig {

    @Resource
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Resource
    private AuthenticationEntryPoint unauthorizedHandler; // 인증 실패 핸들러

    /**
     * BCryptPasswordEncoder Bean 등록
     * 비밀번호 암호화에 사용됩니다.
     *
     * @return new BCryptPasswordEncoder
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Spring Security Filter Chain 정의
     *
     * @param http HttpSecurity
     * @return SecurityFilterChain
     * @throws Exception
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors().and().csrf().and().csrf().disable() // CSRF 보호 기능을 비활성화합니다.
                .exceptionHandling().authenticationEntryPoint(unauthorizedHandler).and() //// 인증 실패 시 동작을 정의
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and() //// 세션 생성 정책을 Stateless로 설정
                .authorizeRequests() // 요청에 대한 접근 제어를 시작합니다.
                /**
                 * antMatchers
                 * 특정 HTTP 요청 패턴에 대해 보안 요구 사항을 설정할 수 있습니다.
                 * HttpSecurity 객체의 authorizeRequests() 메서드와 함께 사용되며,
                 * 특정 경로(예: URL 패턴)에 대한 접근 권한을 설정할 때 사용
                 * */
                .antMatchers("/swagger-ui/**"
                            , "/v3/api-docs/**"
                            ,"/api/auth/signup"
                            , "/api/auth/login"
                            ,"/api/auth/authorize-token"
                            ,"/api/auth/refresh-token"
                            ,"/api/auth/verify-token"
                            ,"/api/auth/logout").permitAll()  // Swagger UI 접근 허용 // "/api/public/**"에 대한 요청은 인증 없이 허용합니다.
                .anyRequest().authenticated(); // 나머지 요청에 대해서는 인증을 요구합니다.
                // JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 이전에 추가
        http    .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
