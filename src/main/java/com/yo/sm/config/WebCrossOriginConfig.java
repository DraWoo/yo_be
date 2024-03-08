package com.yo.sm.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 웹 설정 (CORS 허용)
 * 구성 클래스임을 나타냅니다. Spring이 구동될 때, Spring IoC(Inversion of Control)
 * 컨테이너는 @Configuration이 달린 클래스를 찾아 해당 클래스의 설정 정보를 읽어들임
 */

@Configuration
public class WebCrossOriginConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowCredentials(true)
                .allowedOriginPatterns("http://localhost:9020") //허용할 출처 지정
                .allowedMethods("GET", "POST", "PUT", "DELETE") // 허용할 HTTP 메서드 지정
                .allowedHeaders("*") //허용할 헤더지정
                .allowedMethods("*");// 쿠키 허용 여부 
    }
}
