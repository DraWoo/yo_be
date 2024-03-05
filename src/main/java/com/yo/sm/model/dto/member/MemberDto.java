package com.yo.sm.model.dto.member;

import lombok.Data;

import java.time.LocalDateTime;

@Data
public class MemberDto {
    private String username;
    private String password;
}
