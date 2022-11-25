package io.github.toquery.example.spring.security.oauth2.sso.core;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Data;

/**
 *
 */
@Data
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AppBaseResponse<T> {

    private String message;
    private Integer code;
    private boolean success;
    private T data;


    public static AppBaseResponse<?> success() {
        return AppBaseResponse.success(null);
    }

    public static AppBaseResponse<?> success(Object data) {
        return AppBaseResponse.builder().success(true).code(200).message("成功").data(data).build();
    }

    public static AppBaseResponse<?> fail(String message) {
        return AppBaseResponse.fail(500, message);
    }

    public static AppBaseResponse<?> fail(Integer code) {
        return AppBaseResponse.fail(code, null);
    }

    public static AppBaseResponse<?> fail(Integer code, String message) {
        return AppBaseResponse.builder().success(false).code(code).message(message).build();
    }

}
