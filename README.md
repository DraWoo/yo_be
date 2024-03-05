# Spring Security와 JWT 통합

이 프로젝트는 Spring Boot, Spring Security, JWT(Json Web Token)을 사용하여 RESTful API를 보호하는 방법을 보여줍니다. 보안이 강화된 애플리케이션을 위해 사용자 인증과 함께 API 요청에 대한 접근을 제어합니다.

## 주요 기능

- 사용자 로그인 시 JWT 토큰 발급 및 인증 절차 제공
- JWT를 이용해 보호된 API 엔드포인트 접근 인증
- 회원 가입, 사용자 정보 조회 및 갱신 등 사용자 관리 기능

## 사용된 기술

- **Spring Boot**: 웹 애플리케이션의 빠르고 쉬운 개발을 위한 프레임워크
- **Spring Security**: 인증 및 접근 제어를 위한 강력한 보안 프레임워크
- **JWT**: 사용자 인증 정보를 안전하게 전송하기 위한 JSON 기반의 토큰
- **H2 Database**: 개발 및 테스트 용도로 적합한 인메모리 SQL 데이터베이스
- **Maven**: 프로젝트 관리 및 이해를 돕는 도구

## 시작 방법

프로젝트를 로컬에서 실행하기 위한 단계는 다음과 같습니다.

1. 이 저장소를 클론하거나 다운로드합니다.
2. Maven을 사용하여 의존성을 설치하고 프로젝트를 빌드합니다.
3. Spring Boot 애플리케이션을 실행합니다.
4. `http://localhost:9010` 주소로 애플리케이션에 접속합니다.
5. 제공된 API 엔드포인트로 HTTP 요청을 보내보세요. 인증이 필요한 요청의 경우, 로그인 API를 통해 받은 JWT 토큰을 사용하세요.

