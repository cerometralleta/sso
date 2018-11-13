package org.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.cache.annotation.EnableCaching;

/**
 * Created by lenovo on 2018/6/3.
 */
@EnableOAuth2Sso
@SpringBootApplication
@EnableCaching
public class ClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(ClientApplication.class, args);
    }
}
