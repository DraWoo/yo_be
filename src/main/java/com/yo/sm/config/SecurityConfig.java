package com.yo.sm.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity // Spring Security 설정을 활성화합니다.
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // CSRF 보호 기능을 비활성화합니다.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 STATELESS로 설정합니다.
                .and()
                .authorizeRequests() // 요청에 대한 접근 제어를 시작합니다.
                .antMatchers("/swagger-ui/**", "/v3/api-docs/**").permitAll()  // Swagger UI 접근 허용 // "/api/public/**"에 대한 요청은 인증 없이 허용합니다.
                .anyRequest().authenticated(); // 나머지 요청에 대해서는 인증을 요구합니다.

        // 필요한 경우, 여기에 추가적인 필터 구성을 할 수 있습니다.
        return http.build();
    }
}
