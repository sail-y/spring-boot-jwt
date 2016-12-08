
package com.demo.security;

import com.demo.model.Role;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * Created by YangFan on 2016/11/28 上午11:33.
 * <p/>
 * 最核心的地方，就是提供某个资源对应的权限定义，即getAttributes方法返回的结果。
 * 此类在初始化时，应该取到所有资源及其对应角色的定义。
 */
@Component
public class DemoInvocationSecurityMetadataSourceService implements
        FilterInvocationSecurityMetadataSource {


    private static Map<String, Collection<ConfigAttribute>> resourceMap = null;

    public DemoInvocationSecurityMetadataSourceService() {

    }

    private void loadResourceDefine() {

        /*
         * 应当是资源为key， 权限为value。 资源通常为url， 权限就是那些以ROLE_为前缀的角色。 一个资源可以由多个权限来访问。
         * sparta
         */
        Role r = new Role();
        r.setId(0L);
        r.setName("admin");
        // 假数据
        List<Role> roles = Collections.singletonList(r); // 替换为查询角色列表
        resourceMap = new HashMap<>();

        for (Role role : roles) {
            ConfigAttribute ca = new SecurityConfig(role.getName());

            Map<String, Object> params = new HashMap<>();
            params.put("roleId", role.getId());
            // 查询每个角色对于的权限,我这里假设直接查到了url
            List<String> resources = Collections.singletonList("/user/*/");

            for (String url : resources) {

                /*
                 * 判断资源文件和权限的对应关系，如果已经存在相关的资源url，则要通过该url为key提取出权限集合，将权限增加到权限集合中。
                 * sparta
                 */
                if (resourceMap.containsKey(url)) {

                    Collection<ConfigAttribute> value = resourceMap.get(url);
                    value.add(ca);
                    resourceMap.put(url, value);
                } else {
                    Collection<ConfigAttribute> atts = new ArrayList<>();
                    atts.add(ca);
                    resourceMap.put(url, atts);
                }

            }

        }

    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        loadResourceDefine();
        return null;
    }

    // 根据URL，找到相关的权限配置。
    @Override
    public Collection<ConfigAttribute> getAttributes(Object object)
            throws IllegalArgumentException {

        FilterInvocation filterInvocation = (FilterInvocation) object;
        for (String url : resourceMap.keySet()) {
            RequestMatcher requestMatcher = new AntPathRequestMatcher(url);
            HttpServletRequest httpRequest = filterInvocation.getHttpRequest();

            if (requestMatcher.matches(httpRequest)) {
                return resourceMap.get(url);
            }
        }

        return null;

    }

    @Override
    public boolean supports(Class<?> arg0) {

        return true;
    }

}