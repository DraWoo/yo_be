package com.yo.sm.service.member;

import com.yo.sm.config.JwtTokenProvider;
import com.yo.sm.model.dto.member.MemberDto;
import com.yo.sm.model.dto.member.MemberResponseDto;
import com.yo.sm.model.entity.member.Member;
import com.yo.sm.model.exception.UsernameAlreadyExistsException;
import com.yo.sm.repository.member.MemberRepository;
import javax.annotation.Resource;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;
@Slf4j
@Service
public class MemberService{
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
    public MemberDto saveMember(MemberDto memberDto){
        //엔티티를 Dto로 변환하고 저장
        Member member = new Member();
        //비밀번호 암호화
        String encryptedPassword = passwordEncoder.encode(memberDto.getPassword());
        member.setUsername(memberDto.getUsername());
        member.setPassword(encryptedPassword); // 암호화된 비밀번호로 설정
        member = memberRepository.save(member);

        return memberDto;
    }

    /**
     * ID에 해당하는 사용자 정보를 조회합니다.
     *
     * @param id 조회할 사용자의 ID
     * @return 조회된 사용자 정보를 담은 DTO, 해당 ID의 사용자가 없다면 {@code null}
     */
    public MemberDto getMemberById(Long id) {
        Optional<Member> member = memberRepository.findById(id);
        if (member.isPresent()) {
            MemberDto memberDto = new MemberDto();
            memberDto.setUsername(member.get().getUsername());
            return memberDto;
        }
        return null; // or throw an exception
    }

    /**
     * 주어진 ID에 해당하는 사용자를 수정
     *
     * @param id 수정할 사용자의 ID
     */
    public MemberDto updateMember(Long id, MemberDto memberDto) {
        Optional<Member> existingMember = memberRepository.findById(id);
        if (existingMember.isPresent()) {
            Member member = existingMember.get();
            member.setUsername(memberDto.getUsername());
            member.setPassword(memberDto.getPassword()); // 비밀번호는 암호화 처리가 필요합니다.
            member = memberRepository.save(member);

            return memberDto;
        }
        return null; // or throw an exception
    }

    /**
     * 주어진 ID에 해당하는 사용자를 삭제합니다.
     *
     * @param id 삭제할 사용자의 ID
     */
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
    public MemberResponseDto authenticate(String username, String password) {
        Member member = memberRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        if (!passwordEncoder.matches(password, member.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }

        String token = jwtTokenProvider.generateToken(member.getUsername());
        return createMemberResponseDtoAndAuthenticate(member, token);
    }

    /**
     * 지정된 멤버의 정보와 JWT 토큰을 포함하는 MemberResponseDto 객체를 생성합니다.
     *
     * @param member 정보를 가져올 멤버
     * @return 멤버 정보와 JWT 토큰을 포함하는 MemberResponseDto 객체
     */
    private MemberResponseDto createMemberResponseDtoAndAuthenticate(Member member, String token) {
        MemberResponseDto responseDto = new MemberResponseDto();
        responseDto.setUsername(member.getUsername());
        responseDto.setJwt(token); // JWT 토큰 설정

        return responseDto;
    }

    private MemberDto convertToMemberDto(Member member) {
        MemberDto responseDto = new MemberDto();
        responseDto.setUsername(member.getUsername());

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

    /**
     * 사용자의 가입 요청을 처리하고 새로운 회원 정보를 저장합니다.
     * 사용자 이름이 데이터베이스에 이미 존재하는 경우, 중복 예외를 발생시킵니다.
     *
     * @param memberDto 가입할 사용자 정보
     * @return 저장된 사용자 정보를 포함하는 MemberDto 인스턴스
     * @throws UsernameAlreadyExistsException 사용자 이름이 이미 존재하는 경우 발생
     */
    public MemberDto registerUser(MemberDto memberDto) {
        //사용자ID 중복체크
        if (memberRepository.existsByUsername(memberDto.getUsername())) {
            log.info("회원가입 시도: 사용자 이름 중복 -> {}", memberDto.getUsername());
            throw new UsernameAlreadyExistsException("이미 존재하는 사용자ID 입니다.");
        } else {
            log.info("회원가입 시도: 사용자 이름 -> {}", memberDto.getUsername());
        }


        //가져온 패스워드 인코딩
        String encodedPassword = passwordEncoder.encode(memberDto.getPassword());

        Member newMember = new Member();

        newMember.setUsername(memberDto.getUsername());
        newMember.setPassword(encodedPassword);

        Member createdMember = memberRepository.save(newMember);

        // 저장된 Member 엔티티로부터 MemberDto를 생성합니다.
        return convertToMemberDto(createdMember);
    }
}
