package com.yo.sm.controller.member;

import com.yo.sm.model.ApiResult;
import com.yo.sm.model.dto.member.MemberDto;
import com.yo.sm.service.member.MemberService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;

@RestController
@RequestMapping("/api/auth")
@Tag(name= "Auth API", description = "Authentication 관련 API")
public class AuthController {

    @Resource
    private MemberService memberService;

    @PostMapping("/login")
    @Operation(summary = "로그인", description = "사용자 이름과 비밀번호로 로그인을 시도합니다.")
    public ResponseEntity<ApiResult<MemberDto>> login(@RequestBody MemberDto memberDto) {
        try {
            // 인증 처리
            MemberDto authenticatedMember = memberService.authenticate(memberDto.getUsername(), memberDto.getPassword());
            ApiResult<MemberDto> response = ApiResult.<MemberDto>builder()
                    .code("succeed")
                    .payload(authenticatedMember)
                    .build();
            return ResponseEntity.ok(response);
        } catch (AuthenticationException e) {
            ApiResult<?> response = ApiResult.builder()
                    .code("failed")
                    .message("Authentication failed: " + e.getMessage())
                    .build();
            return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
        }
    }
}
