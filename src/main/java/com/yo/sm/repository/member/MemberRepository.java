package com.yo.sm.repository.member;


import com.yo.sm.model.entity.member.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {

    //username 을 이용해 Member를 찾음
    Optional<Member> findByUsername(String username);

    //사용자ID 중복을 체크함
    boolean existsByUsername(String username);

}
