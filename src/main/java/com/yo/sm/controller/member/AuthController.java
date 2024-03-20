package com.yo.sm.controller.member;

import com.yo.sm.config.JwtTokenProvider;
import com.yo.sm.model.ApiResult;
import com.yo.sm.model.dto.member.MemberDto;
import com.yo.sm.model.dto.member.MemberResponseDto;
import com.yo.sm.model.exception.UsernameAlreadyExistsException;
import com.yo.sm.security.JwtAuthenticationResponse;
import com.yo.sm.service.member.MemberService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import java.util.Date;

import static com.yo.sm.model.ApiResultCode.failed;
import static com.yo.sm.model.ApiResultCode.succeed;

/**
 * 인증 관련 컨트롤러
 * AuthController 클래스는 회원 가입 및 로그인 API를 제공
 * JWT(Jason Web Token)를 이용한 인증
 * 로그인 성공 시 사용자에게 JWT를 발급하고 이 토큰을 사용
 * API 요청의 Authorization 헤더에 추가함으로써 인증된 요청을 할 수 있습니다.
 * 토큰 리프레시는 토큰의 유효기간이 만료되기 전에 새로운 토큰으로 교체하는 기능
 *  ResponseEntity<T>클래스:
 *  HTTP 상태 코드, 헤더 및 응답 본문을 포함할 수 있으며,
 *  RESTful 웹 서비스에서 클라이언트에게 응답 데이터와 함께 추가적인 HTTP 정보를 제공하는 데 주로 사용
 */
@RestController
@RequestMapping("/api/auth")
@Slf4j
@Tag(name= "Auth API", description = "Authentication 관련 API")
public class AuthController {

    @Resource
    private MemberService memberService;

    @Resource
    private JwtTokenProvider jwtTokenProvider;

/**
 * 사용자를 등록하는 메서드
 * 새로운 사용자를 등록하고 결과를 리턴합니다.
 *
 * @param memberDto 등록할 사용자 정보
 * @return ApiResult<MemberDto>
 */
    @PostMapping("/signup")
    @Operation(
            summary = "회원 가입",
            description = "새로운 사용자를 등록합니다.",
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "성공적으로 사용자가 생성되었습니다.",
                            content = @Content(schema = @Schema(implementation = MemberDto.class))
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = "잘못된 요청입니다."
                    )
            }
    )
    public ResponseEntity<?> registerUser(@Valid @RequestBody MemberDto memberDto) {
        try {
            MemberDto newUser = memberService.registerUser(memberDto);
            return ResponseEntity.ok(newUser);
        }
        // 컨트롤러의 예외 처리 부분
        catch (UsernameAlreadyExistsException e) {
            log.error("회원가입 오류: {}", e.getMessage());
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(e.getMessage());
        }
    }

/**
 * 로그인 메서드
 * 사용자가 제공한 정보로 로그인을 시도합니다.
 *
 * @param memberDto 로그인할 사용자 정보
 * @return ResponseEntity<>
 */
    @PostMapping("/login")
    @Operation(summary = "로그인", description = "사용자 이름과 비밀번호로 로그인을 시도합니다.")
    public ResponseEntity<?> login(@RequestBody MemberDto memberDto) {
        try {
            // 사용자 인증을 MemberService를 통해 처리합니다.
            MemberResponseDto authenticatedMember = memberService.authenticate(memberDto.getUsername(), memberDto.getPassword());

            // 로그인 성공 응답을 구성합니다.
            HttpHeaders headers = new HttpHeaders();
            headers.add("Authorization", "Bearer " + authenticatedMember.getJwt());
            return new ResponseEntity<>(authenticatedMember, headers, HttpStatus.OK);
        } catch (UsernameNotFoundException | BadCredentialsException e) {
            // 인증 실패에 대한 응답을 구성합니다.
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("로그인 실패: " + e.getMessage());
        }
    }

/**
 * 로그아웃 메서드
 * 사용자의 요청에 따라 제공된 JWT 토큰을 무효화합니다.
 *
 * @param request 클라이언트의 요청
 * @return 토큰을 무효화하면 200 OK 응답을 반환하며,
 *         토큰이 없는 경우 "Unauthorized request" 메시지와 함께 401 Unauthorized 응답을 반환합니다.
 * 클라이언트 사이드에서 토큰 삭제 => 서버 사이드에 알릴 필요가 있을 시 주석제거 [블랙리스트 토큰 관리등 .]
 */
//    @PostMapping("/logout")
//    public ResponseEntity<?> logout(HttpServletRequest request){
//        String token = jwtTokenProvider.resolveToken(request);
//        if(token != null){
//            jwtTokenProvider.invalidateToken(token);
//            return ResponseEntity.ok("JWT Token has been invalidated");
//        }
//        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized request");
//    }

/**
 * JWT 토큰 갱신 메서드
 * 이 메서드는 클라이언트의 요청에 따라 기존의 JWT 토큰을 갱신합니다.
 *
 * @param request 클라이언트의 요청
 * @return ResponseEntity<JwtAuthenticationResponse>
 */
    @PostMapping("/refresh-token")
    @Operation(summary= "토큰 갱신", description = "기존의 JWT 토큰을 갱신")
    public ResponseEntity<?> refreshAccessToken(HttpServletRequest request) {
        String token = jwtTokenProvider.resolveToken(request);
        if (StringUtils.hasText(token)) {
            try {
                if (jwtTokenProvider.validateToken(token)) {
                    return ResponseEntity.ok(new JwtAuthenticationResponse(token));
                }
            } catch (ExpiredJwtException e) {
                String username = e.getClaims().getSubject();
                String newToken = jwtTokenProvider.generateRefreshToken(username);
                HttpHeaders headers = new HttpHeaders();
                headers.add("Authorization", "Bearer " + newToken);
                return new ResponseEntity<>(new JwtAuthenticationResponse(newToken), headers, HttpStatus.OK);
            } catch (JwtException | IllegalArgumentException e) {
                log.error("Token validation error: {}", e.getMessage());
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Could not refresh token");
    }
/**
 * JWT 토큰 확인 메소드
 * 이 메소드는 클라이언트가 제공한 JWT 토큰의 유효성을 검사합니다.
 *
 * @param request 클라이언트의 요청
 * @return 유효한 토큰인 경우 "이 토큰은 유효합니다."라는 메시지와 함께 200 OK 응답을 반환하며,
 *         유효하지 않은 토큰인 경우 "이 토큰은 유효하지 않습니다."라는 메시지와 함께 401 Unauthorized 응답을 반환합니다.
 *         토큰이 없는 경우 "토큰이 없습니다"라는 메시지와 함께 400 Bad Request 응답을 반환합니다.
 */
    @PostMapping("/verify-token")
    @Operation(summary = "토큰 확인",description = "제공된 JWT 토큰의 유효성을 검사합니다.")
    public ResponseEntity<?> verifyToken(HttpServletRequest request){
        String token = jwtTokenProvider.resolveToken(request);
        if (token != null) {
            try {
                if(jwtTokenProvider.validateToken(token)) {
                    return ResponseEntity.ok("토큰이 유효합니다.");
                }else {
                    // validateToken 메소드가 false를 반환할 경우, JWT 검증에 실패했다는 메시지를 반환합니다.
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("JWT 토큰 검증에 실패하였습니다.");
                }
            } catch (ExpiredJwtException e) {
                String errorMessage = String.format("토큰 만료 오류. 만료된 토큰: %s. 현재 시간: %s, 차이: %d 밀리초.",
                        e.getClaims().getExpiration(), new Date(), Math.abs(new Date().getTime() - e.getClaims().getExpiration().getTime()));
                log.info(errorMessage);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorMessage);
            } catch (Exception e) {
                log.error("토큰 검증 실패: {}", e.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("토큰 검증 실패");
            }
        } else {
            return ResponseEntity.badRequest().body("토큰이 제공되지 않았습니다.");
        }
    }

/**
 * 새로운 JWT 토큰을 발급합니다.
 * 토큰 발급 요청이 들어오면, 사용자 이름을 기반으로 새로운 JWT 토큰을 생성
 * 그리고 이 토큰은 다른 API 요청에 사용
 * 일반적으로, 이 메서드는 인증 과정을 거친 후에 사용자가 서버로부터 안전하게 접근할 수 있는 토큰을 확보하기 위해 사용합니다.
 *
 * @param username 토큰 생성을 위한 사용자 이름
 * @return ResponseEntity<JwtAuthenticationResponse> JWT 토큰을 포함하는 JwtAuthenticationResponse 객체를 반환합니다.
 */
    @PostMapping("/authorize-token")
    @Operation(summary = "토큰 발급", description = "사용자 이름을 받아 새로운 JWT를 발급")
    public ResponseEntity<JwtAuthenticationResponse> authorizeToken(@RequestParam String username){
        String authorizeToken = jwtTokenProvider.generateToken(username);
        JwtAuthenticationResponse response = new JwtAuthenticationResponse(authorizeToken);
        return ResponseEntity.ok(response);
    }

}
