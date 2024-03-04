package com.yo.sm.service.member;

import com.yo.sm.model.dto.member.MemberDto;
import com.yo.sm.model.dto.member.MemberResponseDto;

public interface MemberService {

    MemberDto saveMember(MemberDto memberDto);
    MemberDto getMemberById(Long id);
    MemberDto updateMember(Long id, MemberDto memberDto);
    void deleteMember(Long id);

    //로그인 메서드 추가
    MemberResponseDto authenticate(String username, String password);

    //회원 등록 메서드 추가
    MemberDto registerUser(MemberDto memberDto);
}
