
package com.demo.dto;

import lombok.Data;

import java.util.List;

/**
 * Created by YangFan on 2016/11/28 上午10:53.
 * <p/>
 */
@Data
public class AuthTokenDTO {
    private String token;
    private Long userId;
    private List<String> resourceList;

}
