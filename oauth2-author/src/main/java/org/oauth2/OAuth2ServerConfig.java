package org.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

/**
 * 授权服务器配置
 */
@Slf4j
@Configuration
@EnableAuthorizationServer

// 同时为资源服务器, 其他资源需要token访问
@EnableResourceServer
public class OAuth2ServerConfig extends AuthorizationServerConfigurerAdapter {
    public static final String PERMITALL = "permitAll()";
    public static final String isAuthenticated = "isAuthenticated()";
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    RedisConnectionFactory redisConnectionFactory;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        // /oauth/token_key endpoint, which is secure by default with access rule "denyAll()".
        // You can open it up by injecting a standard SpEL expression into the AuthorizationServerSecurityConfigurer
        // (e.g. "permitAll()" is probably adequate since it is a public key).
        oauthServer.tokenKeyAccess(PERMITALL).checkTokenAccess(isAuthenticated);

        //允许表单认证
        oauthServer.allowFormAuthenticationForClients();
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("SampleClientId")
                .secret("secret")
                .authorizedGrantTypes("authorization_code")
                .scopes("user_info")
                .autoApprove(true);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .tokenStore(new RedisTokenStore(redisConnectionFactory))
                .authenticationManager(authenticationManager);
    }
}
