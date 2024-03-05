package com.yo.sm.model.dto.board;

import com.yo.sm.model.entity.member.Member;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class BoardDto {
    private String title;
    private String content;
    private String username; // 사용자의 username
}