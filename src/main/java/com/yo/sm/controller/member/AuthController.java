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
     * 사용자 회원가입을 처리하는 메서드
     *
     * @param memberDto 사용자가 제공한 회원가입 정보
     * @return ResponseEntity 사용자 정보 또는 에러 메시지를 담은 응답
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
            log.info("사용자 등록 성공 : {}", newUser.getUsername());
            return ResponseEntity.ok(newUser);
        }
        // 컨트롤러의 예외 처리 부분
        catch (UsernameAlreadyExistsException e) {
            log.error("회원가입 오류 - 이미 존재하는 사용자: {}", e.getMessage());
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body(e.getMessage());
        }
    }

    /**
     * 사용자 로그인을 처리하는 메서드
     *
     * @param memberDto 로그인 정보
     * @return ResponseEntity 로그인 성공 시 토큰 정보, 실패 시 에러 메시지
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
            log.info("로그인 성공: {}", memberDto.getUsername());
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
     * 사용자의 JWT 토큰을 갱신하는 메서드
     *
     * @param request 클라이언트 요청
     * @return ResponseEntity 새로운 JWT 토큰 또는 에러 메시지
     */
    @PostMapping("/refresh-token")
    @Operation(summary= "토큰 갱신", description = "기존의 JWT 토큰을 갱신")
    public ResponseEntity<?> refreshAccessToken(HttpServletRequest request) {
        String token = jwtTokenProvider.resolveToken(request);
        if (StringUtils.hasText(token)) {
            try {
                if (jwtTokenProvider.validateToken(token)) {
                    log.info("토큰 갱신 요청 성공");
                    return ResponseEntity.ok(new JwtAuthenticationResponse(token));
                }
            } catch (ExpiredJwtException e) {
                String username = e.getClaims().getSubject();
                String newToken = jwtTokenProvider.generateRefreshToken(username);
                HttpHeaders headers = new HttpHeaders();
                headers.add("Authorization", "Bearer " + newToken);
                log.info("토큰 만료로 인한 갱신 성공: 새 토큰 발급됨");
                return new ResponseEntity<>(new JwtAuthenticationResponse(newToken), headers, HttpStatus.OK);
            } catch (JwtException | IllegalArgumentException e) {
                log.error("토큰 갱신 중 오류 발생: {}", e.getMessage());
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Could not refresh token");
    }
    /**
     * 제공된 JWT 토큰의 유효성을 검사
     *
     * @param request 클라이언트 요청
     * @return ResponseEntity 토큰 유효성 검사 결과
     */
    @PostMapping("/verify-token")
    @Operation(summary = "토큰 확인",description = "제공된 JWT 토큰의 유효성을 검사합니다.")
    public ResponseEntity<?> verifyToken(HttpServletRequest request){
        String token = jwtTokenProvider.resolveToken(request);
        if (token != null) {
            try {
                if(jwtTokenProvider.validateToken(token)) {
                    log.info("토큰 검증 성공: 토큰이 유효함");
                    return ResponseEntity.ok("토큰이 유효합니다.");
                }else {
                    // validateToken 메소드가 false를 반환할 경우, JWT 검증에 실패했다는 메시지를 반환합니다.
                    log.warn("토큰 검증 실패: 토큰이 유효하지 않음");
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
     * 사용자 이름을 받아 새로운 JWT를 발급하고 반환
     *
     * @param username 토큰 생성을 위한 사용자 이름
     * @return ResponseEntity 생성된 JWT 토큰을 포함하는 응답
     */
    @PostMapping("/authorize-token")
    @Operation(summary = "토큰 발급", description = "사용자 이름을 받아 새로운 JWT를 발급")
    public ResponseEntity<JwtAuthenticationResponse> authorizeToken(@RequestParam String username){
        String authorizeToken = jwtTokenProvider.generateToken(username);
        JwtAuthenticationResponse response = new JwtAuthenticationResponse(authorizeToken);
        log.info("새 토큰 발급: 사용자 {}", username);
        return ResponseEntity.ok(response);
    }

}
