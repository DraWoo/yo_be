package com.yo.sm.model.dto.board;

import com.yo.sm.model.entity.member.Member;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class BoardDto {
    private Long id;
    private String title;
    private String content;
    private LocalDateTime createdAt;
    private String username; // 사용자의 username
}