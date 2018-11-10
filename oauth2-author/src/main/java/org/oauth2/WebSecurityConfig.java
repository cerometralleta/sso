package org.oauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.encoding.Md5PasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * Created by ningzuokun on 2017/12/18.
 */
@Configuration
@Order(-1)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 设置 HTTP 验证规则
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        // 关闭csrf验证
        http.csrf().disable();
        http
                .requestMatchers()
                .antMatchers("/oauth/authorize", "/oauth/confirm_access",
                        "/login/**", "/logout/**")
                .and()
                .authorizeRequests()
                .antMatchers("/oauth/**").authenticated()
                .and()
                .formLogin()
                .permitAll();

        http.headers().frameOptions().sameOrigin().disable();
        http.cors().configurationSource(new BootstrapCorsConfigurationSource());
        http.requestMatchers().antMatchers(HttpMethod.OPTIONS, "/oauth/token").and().csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(securityUserDetailService()).passwordEncoder(new Md5PasswordEncoder());
    }


    @Bean
    public SecurityUserDetailService securityUserDetailService() {
        return new SecurityUserDetailService();
    }
}
