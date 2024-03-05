package com.yo.sm.controller.member;

import com.yo.sm.config.JwtTokenProvider;
import com.yo.sm.model.ApiResult;
import com.yo.sm.model.ApiResultCode;
import com.yo.sm.model.dto.member.MemberDto;
import com.yo.sm.model.dto.member.MemberResponseDto;
import com.yo.sm.security.JwtAuthenticationResponse;
import com.yo.sm.service.member.MemberService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;

import static com.yo.sm.model.ApiResultCode.failed;
import static com.yo.sm.model.ApiResultCode.succeed;

/**
 * 인증 관련 컨트롤러
 * AuthController 클래스는 회원 가입 및 로그인 API를 제공
 * JWT(Jason Web Token)를 이용한 인증
 * 로그인 성공 시 사용자에게 JWT를 발급하고 이 토큰을 사용
 * API 요청의 Authorization 헤더에 추가함으로써 인증된 요청을 할 수 있습니다.
 * 토큰 리프레시는 토큰의 유효기간이 만료되기 전에 새로운 토큰으로 교체하는 기능
 */
@RestController
@RequestMapping("/api/auth")
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
    public ResponseEntity<ApiResult<MemberDto>> registerUser(@Valid @RequestBody MemberDto memberDto) {
        MemberDto newUser = memberService.registerUser(memberDto);
        ApiResult<MemberDto> response = ApiResult.<MemberDto>builder()
                .code(succeed)
                .payload(newUser)
                .build();
        return ResponseEntity.ok(response);
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
            MemberResponseDto authenticatedMember = memberService.authenticate(memberDto.getUsername(), memberDto.getPassword());
            String jwtToken = jwtTokenProvider.generateToken(authenticatedMember.getUsername());
            authenticatedMember.setJwt(jwtToken);

            ApiResult<MemberResponseDto> response = ApiResult.<MemberResponseDto>builder()
                    .code(succeed)
                    .payload(authenticatedMember)
                    .build();
            return ResponseEntity.ok(response);
        } catch (BadCredentialsException e) {
            ApiResult<String> response = ApiResult.<String>builder()
                    .code(failed)
                    .message("Authentication failed: " + e.getMessage())
                    .build();
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
        }
    }
    /**
     * 로그아웃 메서드
     * 사용자의 요청에 따라 제공된 JWT 토큰을 무효화합니다.
     *
     * @param request 클라이언트의 요청
     * @return 토큰을 무효화하면 200 OK 응답을 반환하며,
     *         토큰이 없는 경우 "Unauthorized request" 메시지와 함께 401 Unauthorized 응답을 반환합니다.
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request){
        String token = jwtTokenProvider.resolveToken(request);
        if(token != null){
            jwtTokenProvider.invalidateToken(token);
            return ResponseEntity.ok("JWT Token has been invalidated");
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Unauthorized request");
    }

    /**
     * JWT 토큰 갱신 메서드
     * 이 메서드는 클라이언트의 요청에 따라 기존의 JWT 토큰을 갱신합니다.
     *
     * @param request 클라이언트의 요청
     * @return ResponseEntity<JwtAuthenticationResponse>
     */
    @PostMapping("/refresh-token")
    @Operation(summary= "토큰 갱신", description = "기존의 JWT 토큰을 갱신")
    public ResponseEntity<JwtAuthenticationResponse> refreshAccessToken(HttpServletRequest request) {
        String token = jwtTokenProvider.resolveToken(request);
        if (jwtTokenProvider.validateToken(token)) {
            Authentication authentication = jwtTokenProvider.getAuthentication(token);
            String username = (String) authentication.getPrincipal();
            String newToken = jwtTokenProvider.generateRefreshToken(username);
            return ResponseEntity.ok(new JwtAuthenticationResponse(newToken));
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
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
    @PostMapping("/verity-token")
    @Operation(summary = "토큰 확인",description = "제공된 JWT 토큰의 유효성을 검사합니다.")
    public ResponseEntity<?> verityToken(HttpServletRequest request){
        String token = jwtTokenProvider.resolveToken(request);
        if(token == null){
            return ResponseEntity.badRequest().body("토큰이 없습니다.");
        }
        boolean isValid = jwtTokenProvider.validateToken(token);
        if(isValid){
            return ResponseEntity.ok("현재 토큰은 유효합니다.");
        }else{
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("현재 토큰은 유효하지 않습니다.");
        }
    }
    /**
     * 새로운 JWT 토큰을 발급합니다.
     *
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
