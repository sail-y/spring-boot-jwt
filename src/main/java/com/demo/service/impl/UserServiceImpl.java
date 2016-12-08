package com.demo.service.impl;

import com.demo.mapper.UserMapper;
import com.demo.model.User;
import com.demo.service.UserService;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.Map;

@Service("userService")
@Transactional
public class UserServiceImpl implements UserService {

    @Autowired
    private UserMapper userMapper;


    @Override
    public User login(User user) {
        Map<String, Object> params = new HashMap<>();
        params.put("username", user.getUsername());
        params.put("password", DigestUtils.md5Hex(user.getPassword()));

        user = userMapper.login(params);
//        if (user != null) {
//            user.setRoleIds(userMapper.getUserRoleIds(user.getId()));
//        }


        return user;
    }

    @Override
    public User get(Long id) {
        return userMapper.getById(id);
    }

}
