package com.yo.sm.model.dto.member;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class MemberResponseDto {
    private String username;
    private String jwt; // JWT 토큰 필드 추가
}