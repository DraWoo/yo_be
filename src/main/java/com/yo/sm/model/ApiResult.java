package com.yo.sm.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.util.ObjectUtils;
import javax.validation.constraints.NotNull;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * API 요청 결과
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonPropertyOrder( { "code", "message", "payload",
        "currentPage", "totalPage", "totalElement", "hasNext",
        "extra", "error", "now" })
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class ApiResult<T> {

    public ApiResult(ApiResultCode code) {
        this.code = code;
    }

    /**
     * 결과 코드
     */
    @NotNull
    private ApiResultCode code;

    /**
     * 결과 메세지
     */
    private String message;

    /**
     * 요청 결과
     */
    private T payload;

    /**
     * 페이징 정보
     */
    private Integer currentPage = null;
    private Integer totalPage = null;
    private Long totalElement = null;
    private Boolean hasNext = null;

    /**
     * 추가 정보
     */
    private Map<String, Object> extra;

    /**
     * 에러
     */
    private ApiError error;

    /**
     * 에러 코드, {@link ApiError} 사용
     */
    @Deprecated
    private String errorCode;

    /**
     * 로그, {@link ApiError} 사용
     */
    @Deprecated
    private String log;

    /**
     * API 응답 시간 (디버깅 용도)
     */
    @Builder.Default
    private ZonedDateTime now = ZonedDateTime.now();

    private static final Pattern ERROR_CODE_PATTERN = Pattern.compile("<<([A-Z0-9-_]+)>>");
    public void setError(String error) {
        if (!ObjectUtils.isEmpty(error)) {
            Matcher matcher = ERROR_CODE_PATTERN.matcher(error);
            if (matcher.find()) {
                this.errorCode = matcher.group(1);
            }
        }
    }
}
