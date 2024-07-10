package com.example.oauth2server.client.domain;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_POST;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE;
import static org.springframework.util.StringUtils.commaDelimitedListToSet;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.Set;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.DynamicInsert;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@Table
@Entity
@NoArgsConstructor
@DynamicInsert
@Getter
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String clientHash;

    @Column(unique = true)
    private String clientEmail;

    private Instant clientIdIssuedAt;

    private String clientSecret;

    private Instant clientSecretExpiresAt;

    private String clientName;

    @Column(length = 1000)
    private String clientAuthenticationMethods;

    @Column(length = 1000)
    private String authorizationGrantTypes;

    @Column(length = 1000)
    private String redirectUris;

    @Column(length = 1000)
    private String postLogoutRedirectUris;

    @Column(length = 1000)
    private String scopes;

    @Column(length = 2000)
    private ClientSettings clientSettings;

    @Column(length = 2000)
    private TokenSettings tokenSettings;

    @Builder
    public Client(String clientHash, String clientEmail, Instant clientIdIssuedAt, String clientSecret,
                  Instant clientSecretExpiresAt, String clientName, String clientAuthenticationMethods,
                  String authorizationGrantTypes, String redirectUris, String postLogoutRedirectUris, String scopes,
                  ClientSettings clientSettings, TokenSettings tokenSettings) {
        this.clientHash = clientHash;
        this.clientEmail = clientEmail;
        this.clientIdIssuedAt = clientIdIssuedAt;
        this.clientSecret = clientSecret;
        this.clientSecretExpiresAt = clientSecretExpiresAt;
        this.clientName = clientName;
        this.clientAuthenticationMethods = clientAuthenticationMethods;
        this.authorizationGrantTypes = authorizationGrantTypes;
        this.redirectUris = redirectUris;
        this.postLogoutRedirectUris = postLogoutRedirectUris;
        this.scopes = scopes;
        this.clientSettings = clientSettings;
        this.tokenSettings = tokenSettings;
    }

    public static RegisteredClient toObject(Client client) {
        Set<String> clientAuthenticationMethods = commaDelimitedListToSet(client.getClientAuthenticationMethods());
        Set<String> authorizationGrantTypes = commaDelimitedListToSet(client.getAuthorizationGrantTypes());
        Set<String> redirectUris = commaDelimitedListToSet(client.getRedirectUris());
        Set<String> clientScopes = commaDelimitedListToSet(client.getScopes());
        Set<String> postLogoutUris = commaDelimitedListToSet(client.getPostLogoutRedirectUris());

        RegisteredClient.Builder registeredClient = RegisteredClient.withId(client.getClientHash())
                .clientId(client.getClientEmail())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecret(client.getClientSecret())
                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
                .clientName(client.getClientName())
                .clientAuthenticationMethods(authenticationMethods -> clientAuthenticationMethods.forEach(authenticationMethod -> authenticationMethods.add(resolveClientAuthenticationMethod(authenticationMethod))))
                .authorizationGrantTypes((grantTypes) -> authorizationGrantTypes.forEach(grantType -> grantTypes.add(resolveAuthorizationGrantType(grantType))))
                .redirectUris((uris) -> uris.addAll(redirectUris))
                .postLogoutRedirectUris(uris -> uris.addAll(postLogoutUris))
                .scopes((scopes) -> scopes.addAll(clientScopes))
                .clientSettings(client.getClientSettings())
                .tokenSettings(client.getTokenSettings());

        return registeredClient.build();
    }

    private static ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
        if (CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
            return CLIENT_SECRET_BASIC;
        } else if (CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
            return CLIENT_SECRET_POST;
        } else if (NONE.getValue().equals(clientAuthenticationMethod)) {
            return NONE;
        }
        return new ClientAuthenticationMethod(clientAuthenticationMethod);
    }

    private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AUTHORIZATION_CODE;
        } else if (CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return CLIENT_CREDENTIALS;
        } else if (REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return REFRESH_TOKEN;
        }
        return new AuthorizationGrantType(authorizationGrantType);
    }
}
