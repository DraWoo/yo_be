package com.yo.sm.service.member;

import com.yo.sm.config.JwtTokenProvider;
import com.yo.sm.model.dto.member.MemberDto;
import com.yo.sm.model.dto.member.MemberResponseDto;
import com.yo.sm.model.entity.member.Member;
import com.yo.sm.repository.member.MemberRepository;
import javax.annotation.Resource;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
public class MemberServiceImpl implements MemberService{
    @Resource
    private MemberRepository memberRepository;

    @Resource
    private PasswordEncoder passwordEncoder;
    @Resource
    private JwtTokenProvider jwtTokenProvider;

    /**
     * 사용자 정보를 저장합니다.
     * 비밀번호는 암호화하여 저장하며 마지막에 DTO로 변환
     *
     * @param memberDto 저장할 사용자 정보를 담은 DTO
     * @return 저장된 사용자 정보를 담은 DTO
     */
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

    /**
     * ID에 해당하는 사용자 정보를 조회합니다.
     *
     * @param id 조회할 사용자의 ID
     * @return 조회된 사용자 정보를 담은 DTO, 해당 ID의 사용자가 없다면 {@code null}
     */
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

    /**
     * 주어진 ID에 해당하는 사용자를 수정
     *
     * @param id 수정할 사용자의 ID
     */
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

    /**
     * 주어진 ID에 해당하는 사용자를 삭제합니다.
     *
     * @param id 삭제할 사용자의 ID
     */
    @Override
    public void deleteMember(Long id) {
        memberRepository.deleteById(id);
    }


    /**
     * 주어진 사용자 이름과 비밀번호를 바탕으로 사용자를 인증합니다.
     * 인증에 성공하면 사용자 정보와 발급된 JWT 토큰을 담은 DTO를 반환하며, 실패하면 예외를 발생시킵니다.
     *
     * @param username 인증할 사용자의 이름
     * @param password 인증할 사용자의 비밀번호
     * @throws BadCredentialsException 주어진 사용자 이름 또는 비밀번호가 올바르지 않을 때
     * @return 인증된 사용자 정보와 JWT 토큰을 담은 DTO
     */
    @Override
    public MemberResponseDto authenticate(String username, String password) {
        Member member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        return createMemberResponseDtoAndAuthenticate(member);
    }

    /**
     * 지정된 멤버의 정보와 JWT 토큰을 포함하는 MemberResponseDto 객체를 생성합니다.
     *
     * @param member 정보를 가져올 멤버
     * @return 멤버 정보와 JWT 토큰을 포함하는 MemberResponseDto 객체
     */
    private MemberResponseDto createMemberResponseDtoAndAuthenticate(Member member) {
        MemberResponseDto memberDto = new MemberResponseDto();
        memberDto.setId(member.getId());
        memberDto.setUsername(member.getUsername());
        memberDto.setCreatedAt(member.getCreatedAt());

        String token = authenticateAndGenerateToken(member.getUsername());
        memberDto.setJwt(token); // JWT 토큰 설정

        return memberDto;
    }

    private MemberDto convertToMemberDto(Member member) {
        MemberDto responseDto = new MemberDto();
        responseDto.setId(member.getId());
        responseDto.setUsername(member.getUsername());
        responseDto.setCreatedAt(member.getCreatedAt());

        return responseDto;
    }

    /**
     * 사용자 이름과 비밀번호를 사용하여 인증하고 JWT 토큰을 생성합니다.
     *
     * @param username 인증에 사용할 사용자 이름
     * @param password 인증에 사용할 비밀번호
     * @return 생성된 JWT 토큰
     */
    /**
     * 사용자 이름을 받아 토큰을 발행하고 인증합니다.
     *
     * @param username 인증에 사용할 사용자 이름
     * @return 생성된 JWT 토큰
     */
    private String authenticateAndGenerateToken(String username) {
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Authentication 인터페이스의 getPrincipal 메소드를 호출하여 사용자 이름을 구합니다.
        String principal = (String) authentication.getPrincipal();

        return jwtTokenProvider.generateToken(principal);
    }


    @Override
    public MemberDto registerUser(MemberDto memberDto) {
        String encodedPassword = passwordEncoder.encode(memberDto.getPassword());

        Member newMember = new Member();
        newMember.setUsername(memberDto.getUsername());
        newMember.setPassword(encodedPassword);

        Member createdMember = memberRepository.save(newMember);

        MemberDto responseDto = new MemberDto();
        // 저장된 Member 엔티티로부터 MemberDto를 생성합니다.
        return convertToMemberDto(createdMember);
    }
}
