package com.yo.sm.model.entity.board;

import com.yo.sm.model.entity.member.Member;
import lombok.Data;
import org.hibernate.annotations.Comment;

import javax.persistence.*;
import java.time.LocalDateTime;

/**
 * Board 엔티티 클래스는 데이터베이스의 board 테이블에 매핑됩니다.
 */
@Entity
@Table(name="board")
@Data
public class Board {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Comment("PK")
    private Long id;

    @Column(nullable = false)
    @Comment("제목")
    private String title;

    @Column(nullable = false)
    @Comment("내용")
    private String content;

    @Column(nullable = false)
    @Comment("작성 시간")
    private LocalDateTime createdAt;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    @Comment("작성자")
    private Member username;

    // onCreate 메소드에서는 createdAt 필드에 현재 시각(LocalDateTime.now())을 할당
    // 엔티티가 생성되어 데이터베이스에 저장될 때의 시각을 자동으로 기록
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
