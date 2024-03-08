package com.yo.sm.model.dto.member;

import lombok.Data;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.time.LocalDateTime;

@Data
public class MemberDto {
    @NotNull(message = "사용자 이름은 필수값입니다.")
    private String username;
    @NotNull(message = "비밀번호는 필수값입니다.")
    private String password;
}
