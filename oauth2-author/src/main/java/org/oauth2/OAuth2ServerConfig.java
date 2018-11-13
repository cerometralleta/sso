package org.oauth2;

import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * 授权服务器配置
 */
@Slf4j
@Configuration
@EnableAuthorizationServer
public class OAuth2ServerConfig extends AuthorizationServerConfigurerAdapter {
    private static final String public_key = "pubkey.txt";
    public static final String USER_DETAILS = "user";
    public static final String PERMITALL = "permitAll()";
    public static final String isAuthenticated = "isAuthenticated()";

    @Autowired
    AuthenticationManager authenticationManager;

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
                .authorizedGrantTypes("authorization_code", "password")
                .scopes("user_info")
                .autoApprove(true);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), jwtAccessTokenConverter()));
        endpoints.tokenStore(jwtTokenStore()).tokenEnhancer(tokenEnhancerChain).authenticationManager(authenticationManager);
    }

    @Bean
    public DefaultAccessTokenConverter redisAccessTokenConverter() {
        DefaultAccessTokenConverter defaultAccessTokenConverter = new DefaultAccessTokenConverter();
        defaultAccessTokenConverter.setUserTokenConverter(new SecurityUserAuthenticationConverter());
        return defaultAccessTokenConverter;
    }

    @Bean
    public TokenStore jwtTokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    // token增强
    @Bean
    public TokenEnhancer tokenEnhancer() {
        return new CustomTokenEnhancer();
    }

    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();

        //             对称加密
//        converter.setSigningKey("123");
        DefaultAccessTokenConverter defaultAccessTokenConverter = new DefaultAccessTokenConverter();
        defaultAccessTokenConverter.setUserTokenConverter(new SecurityUserAuthenticationConverter());
        converter.setAccessTokenConverter(defaultAccessTokenConverter);
        converter.setVerifierKey(obtainPubKey());
        KeyStoreKeyFactory keyStoreKeyFactory =
                new KeyStoreKeyFactory(new ClassPathResource("mytest.jks"), "mypass".toCharArray());
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair("mytest"));
        return converter;
    }

    // 获取本地公钥
    private String obtainPubKey() {
        org.springframework.core.io.Resource resource = new ClassPathResource(public_key);
        try (BufferedReader br = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
            String pubKey = br.lines().collect(Collectors.joining("\n"));
            log.info("客户端JWT公钥:{}", pubKey);
            return pubKey;
        } catch (IOException ioe) {
            log.error("客户端JWT公钥获取失败:{}", ioe);
        }
        return null;
    }

    // 自定义Token增强
    public static class CustomTokenEnhancer implements TokenEnhancer {

        @Override
        public OAuth2AccessToken enhance(
                OAuth2AccessToken accessToken,
                OAuth2Authentication authentication) {

            // 添加自定义属性
            AdditionalInfo additionalInfo = new AdditionalInfo();
            new ModelMapper().map(authentication.getUserAuthentication().getPrincipal(), additionalInfo);

            Map<String, Object> additionalInformation = new HashMap<>();
            additionalInformation.put(USER_DETAILS, additionalInfo);
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInformation);
            return accessToken;
        }
    }

}
