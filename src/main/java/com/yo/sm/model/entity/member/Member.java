package com.yo.sm.model.entity.member;

import com.fasterxml.jackson.annotation.JsonIgnore;
import javax.persistence.*;

import lombok.Data;
import org.hibernate.annotations.Comment;

import java.time.LocalDateTime;

/**
 * Member 엔티티 클래스는 데이터베이스의 member 테이블
 */
@Entity // 이 클래스를 JPA 엔티티로 지정
@Table(name = "member") // 이 엔티티가 연결될 데이터베이스 테이블의 이름을 지정
@Data
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Comment("PK")
    private Long id;

    @Column(name = "username", nullable = false, length = 50)
    @Comment("로그인 아이디")
    private String username;

    @Column(name = "password")
    @Comment("로그인 비밀번호")
    @JsonIgnore
    private String password;

    @Column(nullable = false)
    @Comment("계정 생성 시간")
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

}
