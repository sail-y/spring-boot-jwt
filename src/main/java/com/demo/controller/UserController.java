package com.demo.controller;

import com.demo.dto.AuthTokenDTO;
import com.demo.jwt.AuthTokenDetails;
import com.demo.jwt.JsonWebTokenUtility;
import com.demo.model.User;
import com.demo.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;

/**
 * 用户控制器
 */
@RestController
@RequestMapping("/user")
@Slf4j
public class UserController {

    @Autowired
    private UserService userService;

    private JsonWebTokenUtility tokenService = new JsonWebTokenUtility();

    /**
     * 用户登录
     *
     * @param u 用户对象
     * @return
     */
    @RequestMapping(value = "/login", method = RequestMethod.POST)
    public AuthTokenDTO login(@RequestBody User u) {
        AuthTokenDTO authToken = null;

        User user = userService.login(u);

        if (user != null) {


            AuthTokenDetails authTokenDetails = new AuthTokenDetails();
            authTokenDetails.setId(user.getId());
            authTokenDetails.setUsername(user.getUsername());
            authTokenDetails.setExpirationDate(buildExpirationDate());
            // TODO: 2016/12/8 这里要查询用户拥有的角色，会结合JWT和Spring Security进行验证。
            authTokenDetails.setRoleNames(Collections.singletonList("admin"));

            // Create auth token
            String jwt = tokenService.createJsonWebToken(authTokenDetails);
            if (jwt != null) {
                authToken = new AuthTokenDTO();
                authToken.setToken(jwt);
                authToken.setUserId(user.getId());
            }
        } else {
            throw new RuntimeException("用户名或密码错误");
        }

        return authToken;
    }


    private Date buildExpirationDate() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR_OF_DAY, 1);
        return calendar.getTime();
    }


    /**
     * 用户详情
     *
     * @param userId
     * @return
     */
    @RequestMapping(value = "/{userId}/", method = RequestMethod.GET)
    public User getUserById(@PathVariable("userId") Long userId) {
        User user = userService.get(userId);
        user.setPassword(null);
        return user;
    }

}
