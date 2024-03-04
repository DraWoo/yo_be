package com.yo.sm.service.member;

import com.yo.sm.model.dto.member.MemberDto;

public interface MemberService {

    MemberDto saveMember(MemberDto memberDto);
    MemberDto getMemberById(Long id);
    MemberDto updateMember(Long id, MemberDto memberDto);
    void deleteMember(Long id);

    //로그인 메서드 추가
    MemberDto authenticate(String username, String password);
}
