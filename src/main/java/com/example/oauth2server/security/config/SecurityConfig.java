package com.example.oauth2server.security.config;

import static org.springframework.security.config.Customizer.withDefaults;

import com.example.oauth2server.client.domain.ClientRepository;
import com.example.oauth2server.client.repository.CustomRegisteredClientRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // 출처: https://velog.io/@juhyeon1114/Spring-OAuth2-%EC%9D%B8%EC%A6%9D-%EC%84%9C%EB%B2%84-%EA%B5%AC%EC%B6%95%ED%95%98%EA%B8%B0
    // https://sg-choi.tistory.com/647

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(withDefaults());
        http.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor( // 인가 실패에 대한 처리를 정의
                new LoginUrlAuthenticationEntryPoint("/login")
                ,new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
        ));
        http.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(withDefaults()));

        return http.build();
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.authorizeHttpRequests(authorize -> {
            authorize
                    .requestMatchers(
                            "/",
                            "/login",
                            "/api/v1/oauth/**",
                            "/api/v1/client/**"
                    )
                    .permitAll()
                    .anyRequest().authenticated();
        });
        http.formLogin(withDefaults());
        return http.build();
    }

    // TODO 커스텀 후 삭제
//    @Bean
//    public UserDetailsService userDetailsService() {
//        UserDetails userDetails = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("1234")
//                .roles("USER")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }

    // TODO 커스텀 후 삭제
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientName("Your client name")
//                .clientId("your-client")
//                .clientSecret("{noop}your-secret") // 실제 운영환경에서는 임의의 문자열을 사용하고, 코드에 올리면 안됨
//                .clientAuthenticationMethods(methods -> {
//                    methods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
//                })
//                .authorizationGrantTypes(types -> {
//                    types.add(AuthorizationGrantType.AUTHORIZATION_CODE);
//                    types.add(AuthorizationGrantType.REFRESH_TOKEN);
//                })
//                .redirectUris(uri -> {
//                    uri.add("http://localhost:8090");
//                })
//                .postLogoutRedirectUri("http://localhost:8090")
//                .scopes(scope -> {
//                    scope.add(OidcScopes.OPENID);
//                    scope.add(OidcScopes.PROFILE);
//                })
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(oidcClient);
//    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .authorizationEndpoint("/api/v1/oauth/authorize")
                .tokenEndpoint("/api/v1/oauth/token")
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    // TODO RSA Util 따로 생성
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        return keyPair;
    }


}
