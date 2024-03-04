package com.yo.sm.service.member;

import com.yo.sm.config.JwtTokenProvider;
import com.yo.sm.model.dto.member.MemberDto;
import com.yo.sm.model.entity.member.Member;
import com.yo.sm.repository.member.MemberRepository;
import javax.annotation.Resource;

import org.apache.tomcat.util.net.openssl.ciphers.Authentication;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class MemberServiceImpl implements MemberService{
    @Resource
    private MemberRepository memberRepository;

    @Resource
    private PasswordEncoder passwordEncoder;
    @Resource
    private JwtTokenProvider jwtTokenProvider;

    @Override
    public MemberDto saveMember(MemberDto memberDto){
        //엔티티를 Dto로 변환하고 저장
        Member member = new Member();
        //비밀번호 암호화
        String encryptedPassword = passwordEncoder.encode(memberDto.getPassword());
        member.setUsername(memberDto.getUsername());
        member.setPassword(encryptedPassword); // 암호화된 비밀번호로 설정
        member = memberRepository.save(member);

        //엔티티를 DTO로 변환하여 반환
        memberDto.setId(member.getId());
        memberDto.setCreatedAt(member.getCreatedAt());
        return memberDto;
    }

    @Override
    public MemberDto getMemberById(Long id) {
        Optional<Member> member = memberRepository.findById(id);
        if (member.isPresent()) {
            MemberDto memberDto = new MemberDto();
            memberDto.setId(member.get().getId());
            memberDto.setUsername(member.get().getUsername());
            memberDto.setCreatedAt(member.get().getCreatedAt());
            return memberDto;
        }
        return null; // or throw an exception
    }

    @Override
    public MemberDto updateMember(Long id, MemberDto memberDto) {
        Optional<Member> existingMember = memberRepository.findById(id);
        if (existingMember.isPresent()) {
            Member member = existingMember.get();
            member.setUsername(memberDto.getUsername());
            member.setPassword(memberDto.getPassword()); // 비밀번호는 암호화 처리가 필요합니다.
            member = memberRepository.save(member);

            memberDto.setId(member.getId());
            memberDto.setCreatedAt(member.getCreatedAt());
            return memberDto;
        }
        return null; // or throw an exception
    }

    @Override
    public void deleteMember(Long id) {
        memberRepository.deleteById(id);
    }

    @Override
    public MemberDto authenticate(String username, String password) {
        return memberRepository.findByUsername(username)
                .filter(member -> passwordEncoder.matches(password, member.getPassword()))
                .map(member -> createMemberDtoAndAuthenticate(member, username))
                // 잘못된 자격 증명을 제시했음을 나타내는데 사용되는 표준 예외
                .orElseThrow(() -> new BadCredentialsException("Login failed for user " + username));
    }

    private MemberDto createMemberDtoAndAuthenticate(Member member, String username) {
        MemberDto memberDto = new MemberDto();
        memberDto.setId(member.getId());
        memberDto.setUsername(member.getUsername());
        memberDto.setCreatedAt(member.getCreatedAt());

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(username, null, null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtTokenProvider.generateToken(authentication);

        return memberDto;
    }
}
