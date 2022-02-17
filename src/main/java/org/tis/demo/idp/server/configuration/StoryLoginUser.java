package org.tis.demo.idp.server.configuration;

import lombok.Data;

import java.io.Serializable;
import java.util.Set;

/**
 * 当前登录用户
 */
@Data
public class StoryLoginUser implements Serializable {
    private static final long serialVersionUID = -5339236104490631398L;
    private Long id;
    private String account;
    private String name;
    private String email;
    private String avatar;
    private String status;
    private Set<String> authoritys;
    public StoryLoginUser() {
        // 默认构造函数
    }
    // ...
}