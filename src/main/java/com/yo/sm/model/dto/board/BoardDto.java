package com.yo.sm.model.dto.board;

import com.yo.sm.model.entity.member.Member;
import lombok.Data;

import java.time.LocalDateTime;

@Data
public class BoardDto {
    private Long id; // 게시글의 ID
    private String title; // 게시글의 제목
    private String content; // 게시글의 내용
    private String username; // 게시글을 작성한 사용자의 사용자 이름
    private LocalDateTime createdAt; // 게시글 작성 시간
    private LocalDateTime updatedAt; // 게시글 수정 시간
}