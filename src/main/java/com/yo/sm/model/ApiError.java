package com.yo.sm.model;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.*;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * API 에러
 */
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@ToString
@Builder
@JsonPropertyOrder({ "type", "code", "violations", "log" })
public class ApiError {

    /**
     * 에러 타입
     */
    private String type;

    /**
     * 에러 코드
     */
    private String code;

    /**
     * 에러 추가 정보
     */
    private List<Map<String, Object>> violations;

    /**
     * 로그
     */
    private String log;

    public void addViolation(Map<String, Object> violation) {

        if (ObjectUtils.isEmpty(this.violations)) {
            this.violations = new ArrayList<>();
        }

        violations.add(violation);
    }
}
