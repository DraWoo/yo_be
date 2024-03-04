package com.yo.sm.model.dto.member;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class MemberResponseDto {
    private Long id;
    private String username;
    private LocalDateTime createdAt;
    private String jwt; // JWT 토큰 필드 추가
}