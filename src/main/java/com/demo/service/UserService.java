package com.demo.service;

import com.demo.jwt.AuthTokenDetails;
import com.demo.model.User;

import java.util.List;

/**
 * 用户Service
 *
 * @author yangfan
 */
public interface UserService {

    /**
     * 用户登录
     *
     * @param user 里面包含登录名和密码
     * @return 用户对象
     */
    User login(User user);


    /**
     * 获得用户对象
     *
     * @param id
     * @return
     */
    User get(Long id);

}
