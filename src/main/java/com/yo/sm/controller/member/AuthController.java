package com.yo.sm.controller.member;

import com.yo.sm.config.JwtTokenProvider;
import com.yo.sm.model.ApiResult;
import com.yo.sm.model.ApiResultCode;
import com.yo.sm.model.dto.member.MemberDto;
import com.yo.sm.model.dto.member.MemberResponseDto;
import com.yo.sm.service.member.MemberService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

import static com.yo.sm.model.ApiResultCode.failed;
import static com.yo.sm.model.ApiResultCode.succeed;

@RestController
@RequestMapping("/api/auth")
@Tag(name= "Auth API", description = "Authentication 관련 API")
public class AuthController {

    @Resource
    private MemberService memberService;

    @Resource
    private JwtTokenProvider jwtTokenProvider;

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
    public ResponseEntity<ApiResult<MemberDto>> registerUser(@RequestBody MemberDto memberDto) {
        MemberDto newUser = memberService.registerUser(memberDto);
        ApiResult<MemberDto> response = ApiResult.<MemberDto>builder()
                .code(succeed)
                .payload(newUser)
                .build();
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    @Operation(summary = "로그인", description = "사용자 이름과 비밀번호로 로그인을 시도합니다.")
    public ResponseEntity<?> login(@RequestBody MemberDto memberDto) {
        try {
            MemberResponseDto authenticatedMember = memberService.authenticate(memberDto.getUsername(), memberDto.getPassword());

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

}
