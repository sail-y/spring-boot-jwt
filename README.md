

这篇文章我们来讲一下如何集成JWT到Spring Boot项目中来完成接口的权限验证。

# JWT


JWT是一种用于双方之间传递安全信息的简洁的、URL安全的表述性声明规范。JWT作为一个开放的标准（ RFC 7519 ），定义了一种简洁的，自包含的方法用于通信双方之间以Json对象的形式安全的传递信息。因为数字签名的存在，这些信息是可信的，JWT可以使用HMAC算法或者是RSA的公私秘钥对进行签名。
如何使用JWT？

在身份鉴定的实现中，传统方法是在服务端存储一个session，给客户端返回一个cookie，而使用JWT之后，当用户使用它的认证信息登陆系统之后，会返回给用户一个JWT，用户只需要本地保存该token（通常使用local storage，也可以使用cookie）即可。
<!--more-->
因为用户的状态在服务端的内存中是不存储的，所以这是一种 无状态 的认证机制。服务端的保护路由将会检查请求头 Authorization 中的JWT信息，如果合法，则允许用户的行为。由于JWT是自包含的，因此减少了需要查询数据库的需要。

JWT的这些特性使得我们可以完全依赖其无状态的特性提供数据API服务，甚至是创建一个下载流服务。因为JWT并不使用Cookie的，所以你可以使用任何域名提供你的API服务而不需要担心跨域资源共享问题（CORS）。
大概就是这样：
![](http://img1.tuicool.com/UfIbUjj.png!web)

# Spring Boot集成
我是勤劳的搬运工，[这应该是翻译老外的东西](http://www.jdon.com/dl/best/json-web-tokens-spring-cloud-microservices.html)，项目地址：https://github.com/thomas-kendall/trivia-microservices。

废话不多说了，我直接上代码,依然是搬运工。
我是gradle构建的，就是引入一些依赖的jar包。顺便推荐一下阿里云的中央仓库

	http://maven.aliyun.com/nexus/content/groups/public/

```groovy
dependencies {
	compile('org.springframework.boot:spring-boot-starter-aop')
	compile('org.springframework.boot:spring-boot-starter-security')
	compile('org.mybatis.spring.boot:mybatis-spring-boot-starter:1.1.1')
	compile('org.springframework.boot:spring-boot-starter-web')
    compile('com.google.guava:guava:20.0')
    compile('com.alibaba:druid:0.2.9')
	compile('org.apache.commons:commons-lang3:3.5')
	compile('commons-collections:commons-collections:3.2.2')
	compile('commons-codec:commons-codec:1.10')
	compile('com.github.pagehelper:pagehelper:4.1.6')
	compile('io.jsonwebtoken:jjwt:0.6.0')
	runtime('mysql:mysql-connector-java')
	compileOnly('org.projectlombok:lombok')
	testCompile('org.springframework.boot:spring-boot-starter-test')
}
```
下面这个是类是产生token的主要类

```java
/**
 * Created by YangFan on 2016/11/28 上午10:01.
 * <p/>
 */
@Slf4j
public class JsonWebTokenUtility {
    private SignatureAlgorithm signatureAlgorithm;
    private Key secretKey;

    public JsonWebTokenUtility() {

        // 这里不是真正安全的实践
        // 为了简单，我们存储一个静态key在这里，
        signatureAlgorithm = SignatureAlgorithm.HS512;
        String encodedKey =
                "L7A/6zARSkK1j7Vd5SDD9pSSqZlqF7mAhiOgRbgv9Smce6tf4cJnvKOjtKPxNNnWQj+2lQEScm3XIUjhW+YVZg==";
        secretKey = deserializeKey(encodedKey);
    }

    public String createJsonWebToken(AuthTokenDetails authTokenDetails) {
        String token =
                Jwts.builder().setSubject(authTokenDetails.getId().toString())
                        .claim("username", authTokenDetails.getUsername())
                        .claim("roleNames", authTokenDetails.getRoleNames())
                        .setExpiration(authTokenDetails.getExpirationDate())
                        .signWith(getSignatureAlgorithm(),
                                getSecretKey()).compact();
        return token;
    }

    private Key deserializeKey(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        Key key =
                new SecretKeySpec(decodedKey, getSignatureAlgorithm().getJcaName());
        return key;
    }

    private Key getSecretKey() {
        return secretKey;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public AuthTokenDetails parseAndValidate(String token) {
        AuthTokenDetails authTokenDetails = null;
        try {
            Claims claims =
                    Jwts.parser().setSigningKey(getSecretKey()).parseClaimsJws(token).getBody();
            String userId = claims.getSubject();
            String username = (String) claims.get("username");
            List<String> roleNames = (List) claims.get("roleNames");
            Date expirationDate = claims.getExpiration();

            authTokenDetails = new AuthTokenDetails();
            authTokenDetails.setId(Long.valueOf(userId));
            authTokenDetails.setUsername(username);
            authTokenDetails.setRoleNames(roleNames);
            authTokenDetails.setExpirationDate(expirationDate);
        } catch (JwtException ex) {
            log.error(ex.getMessage(), ex);
        }
        return authTokenDetails;
    }

    private String serializeKey(Key key) {
        String encodedKey =
                Base64.getEncoder().encodeToString(key.getEncoded());
        return encodedKey;
    }
}
```

现在我们需要一个定制授权过滤器，将能读取请求头部信息，在Spring中已经有一个这样的授权Filter称为：RequestHeaderAuthenticationFilter，我们只要扩展继承即可：

```java
@Component
public class JsonWebTokenAuthenticationFilter extends RequestHeaderAuthenticationFilter {

    public JsonWebTokenAuthenticationFilter() {
        // Don't throw exceptions if the header is missing
        this.setExceptionIfHeaderMissing(false);

        // This is the request header it will look for
        this.setPrincipalRequestHeader("Authorization");
    }

    @Override
    @Autowired
    public void setAuthenticationManager(
            AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }
}
```

在这里，头部信息将被转换为Spring Authentication对象，名称为PreAuthenticatedAuthenticationToken
我们需要一个授权提供者读取这个记号，然后验证它，然后转换为我们自己的定制授权对象，就是把header里的token转化成我们自己的授权对象。然后把解析之后的对象返回给Spring Security，这里就相当于完成了token->session的转换。

```java

@Component
public class JsonWebTokenAuthenticationProvider implements AuthenticationProvider {

    private JsonWebTokenUtility tokenService = new JsonWebTokenUtility();

    @Override
    public Authentication authenticate(Authentication authentication)
            throws AuthenticationException {
        Authentication authenticatedUser = null;
        // Only process the PreAuthenticatedAuthenticationToken
        if (authentication.getClass().
                isAssignableFrom(PreAuthenticatedAuthenticationToken.class)
                && authentication.getPrincipal() != null) {
            String tokenHeader = (String) authentication.getPrincipal();
            UserDetails userDetails = parseToken(tokenHeader);
            if (userDetails != null) {
                authenticatedUser =
                        new JsonWebTokenAuthentication(userDetails, tokenHeader);
            }
        } else {
            // It is already a JsonWebTokenAuthentication
            authenticatedUser = authentication;
        }
        return authenticatedUser;
    }

    private UserDetails parseToken(String tokenHeader) {

        UserDetails principal = null;
        AuthTokenDetails authTokenDetails =
                tokenService.parseAndValidate(tokenHeader);

        if (authTokenDetails != null) {
            List<GrantedAuthority> authorities =
                    authTokenDetails.getRoleNames().stream()
                            .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
            // userId介入Spring Security
            principal = new User(authTokenDetails.getId().toString(), "",
                    authorities);
        }

        return principal;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return
                authentication.isAssignableFrom(
                        PreAuthenticatedAuthenticationToken.class)||
                        authentication.isAssignableFrom(
                                JsonWebTokenAuthentication.class);
    }

}

```

# Spring Security

上面完成了JWT和Spring Boot的集成。
接下来我们再如何把自己的权限系统也接入Spring Security。
刚才已经展示了通过JsonWebTokenAuthenticationProvider的处理，我们已经能通过header的token来识别用户，并拿到他的角色和userId等信息。

配置Spring Security有3个不可缺的类。		
首先配置拦截器，拦截所有的请求。

```java
/**
 * Created by YangFan on 2016/11/28 上午11:32.
 * <p/>
 */
@Component
public class DemoSecurityInterceptor extends AbstractSecurityInterceptor
        implements Filter {


    @Autowired
    private FilterInvocationSecurityMetadataSource securityMetadataSource;

    @Autowired
    @Override
    public void setAccessDecisionManager(AccessDecisionManager accessDecisionManager) {
        super.setAccessDecisionManager(accessDecisionManager);
    }

    @Autowired
    @Override
    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        super.setAuthenticationManager(authenticationManager);
    }


    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        FilterInvocation fi = new FilterInvocation(request, response, chain);
        invoke(fi);

    }


    public Class<? extends Object> getSecureObjectClass() {
        return FilterInvocation.class;
    }


    public void invoke(FilterInvocation fi) throws IOException, ServletException {

        InterceptorStatusToken token = super.beforeInvocation(fi);

        try {
            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
        } finally {
            super.afterInvocation(token, null);
        }

    }


    @Override
    public SecurityMetadataSource obtainSecurityMetadataSource() {
        return this.securityMetadataSource;
    }




    public void destroy() {

    }

    public void init(FilterConfig filterconfig) throws ServletException {

    }

}

```

然后是把我们自己的权限数据加载到Spring Security中。

```java
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
            List<String> resources = Collections.singletonList("/user/*");

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
```

现在我们拿到了用户的角色，也拿到了系统里有的角色和权限，就需要判断他是否有这个权限了，配置如下：

```java
/**
 * Created by YangFan on 2016/11/28 下午12:19.
 * <p/>
 * AccessdecisionManager在Spring security中是很重要的。
 * <p>
 * 在验证部分简略提过了，所有的Authentication实现需要保存在一个GrantedAuthority对象数组中。
 * 这就是赋予给主体的权限。 GrantedAuthority对象通过AuthenticationManager
 * 保存到 Authentication对象里，然后从AccessDecisionManager读出来，进行授权判断。
 * <p>
 * Spring Security提供了一些拦截器，来控制对安全对象的访问权限，例如方法调用或web请求。
 * 一个是否允许执行调用的预调用决定，是由AccessDecisionManager实现的。
 * 这个 AccessDecisionManager 被AbstractSecurityInterceptor调用，
 * 它用来作最终访问控制的决定。 这个AccessDecisionManager接口包含三个方法：
 * <p>
 * void decide(Authentication authentication, Object secureObject,
 * List<ConfigAttributeDefinition> config) throws AccessDeniedException;
 * boolean supports(ConfigAttribute attribute);
 * boolean supports(Class clazz);
 * <p>
 * 从第一个方法可以看出来，AccessDecisionManager使用方法参数传递所有信息，这好像在认证评估时进行决定。
 * 特别是，在真实的安全方法期望调用的时候，传递安全Object启用那些参数。
 * 比如，让我们假设安全对象是一个MethodInvocation。
 * 很容易为任何Customer参数查询MethodInvocation，
 * 然后在AccessDecisionManager里实现一些有序的安全逻辑，来确认主体是否允许在那个客户上操作。
 * 如果访问被拒绝，实现将抛出一个AccessDeniedException异常。
 * <p>
 * 这个 supports(ConfigAttribute) 方法在启动的时候被
 * AbstractSecurityInterceptor调用，来决定AccessDecisionManager
 * 是否可以执行传递ConfigAttribute。
 * supports(Class)方法被安全拦截器实现调用，
 * 包含安全拦截器将显示的AccessDecisionManager支持安全对象的类型。
 */
@Component
public class DemoAccessDecisionManager implements AccessDecisionManager {

    public void decide(Authentication authentication, Object object,
                       Collection<ConfigAttribute> configAttributes)
            throws AccessDeniedException, InsufficientAuthenticationException {

        if (configAttributes == null) {
            return;
        }

        for (ConfigAttribute ca : configAttributes) {

            String needRole = ca.getAttribute();

            //ga 为用户所被赋予的权限。 needRole 为访问相应的资源应该具有的权限。
            for (GrantedAuthority ga : authentication.getAuthorities()) {

                if (needRole.trim().equals(ga.getAuthority().trim())) {

                    return;
                }

            }

        }

        throw new AccessDeniedException("没有权限进行操作！");

    }

    public boolean supports(ConfigAttribute attribute) {

        return true;

    }

    public boolean supports(Class<?> clazz) {
        return true;

    }


}
```

我们试试登录的接口：
![](http://7xs4nh.com1.z0.glb.clouddn.com/login.png)

然后我们用这个token来调用另外一个接口。
我们先试试不传Token会返回什么

![](http://7xs4nh.com1.z0.glb.clouddn.com/spring-boot-jwt-user-0.png)

判断没有登录，现在再来试试带上token的请求。
已经成功的请求到了数据。
![](http://7xs4nh.com1.z0.glb.clouddn.com/spring-boot-jwt-1.png)


好了，核心配置就是这些，我把这些代码上传github上，有需要的可以下载下来看看。里面的角色和权限都是虚拟数据，应用还需要自行修改代码。
