package com.example.oauth2server.dto;

import static org.springframework.util.StringUtils.collectionToCommaDelimitedString;

import com.example.oauth2server.client.domain.Client;
import jakarta.validation.constraints.Email;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import lombok.Data;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@Data
public class ClientSaveRequestDto {

    private String clientHash;

    @Email
    private String clientEmail;

    private Instant clientIdIssuedAt;

    private String clientSecret;

    private Instant clientSecretExpiresAt;

    private String clientName;

    private String clientAuthenticationMethods;

    private String authorizationGrantTypes;

    private String redirectUris;

    private String postLogoutRedirectUris;

    private String scopes;

    private ClientSettings clientSettings;

    private TokenSettings tokenSettings;

    public Client toEntity(RegisteredClient registeredClient){
        List<String> clientAuthenticationMethods = List.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue());
        List<String> authorizationGrantTypes = List.of(AuthorizationGrantType.AUTHORIZATION_CODE.getValue(), AuthorizationGrantType.REFRESH_TOKEN.getValue());
        List<String> scopes = List.of(OidcScopes.OPENID, OidcScopes.PROFILE);
        return Client.builder()
                .clientHash(registeredClient.getId())
                .clientEmail(registeredClient.getClientId())
                .clientIdIssuedAt(registeredClient.getClientIdIssuedAt())
                .clientSecretExpiresAt(registeredClient.getClientSecretExpiresAt())
                .clientName(registeredClient.getClientName())
                .clientAuthenticationMethods(collectionToCommaDelimitedString(clientAuthenticationMethods))
                .authorizationGrantTypes(collectionToCommaDelimitedString(authorizationGrantTypes))
                .redirectUris(collectionToCommaDelimitedString(registeredClient.getRedirectUris()))
                .postLogoutRedirectUris(collectionToCommaDelimitedString(registeredClient.getPostLogoutRedirectUris()))
                .scopes(collectionToCommaDelimitedString(scopes))
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .tokenSettings(registeredClient.getTokenSettings())
                .build();
    }

    public Client toEntity(ClientSaveRequestDto dto){
        return Client.builder()
                .clientHash(UUID.randomUUID().toString())
                .clientEmail(dto.getClientEmail())
                .clientIdIssuedAt(dto.getClientIdIssuedAt())
                .clientSecretExpiresAt(dto.getClientSecretExpiresAt())
                .clientName(dto.getClientName())
                .clientAuthenticationMethods(collectionToCommaDelimitedString(
                        Collections.singleton(clientAuthenticationMethods)))
                .authorizationGrantTypes(collectionToCommaDelimitedString(
                        Collections.singleton(authorizationGrantTypes)))
                .redirectUris(collectionToCommaDelimitedString(Collections.singleton(dto.getRedirectUris())))
                .postLogoutRedirectUris(collectionToCommaDelimitedString(
                        Collections.singleton(dto.getPostLogoutRedirectUris())))
                .scopes(collectionToCommaDelimitedString(Collections.singleton(dto.getScopes())))
                .clientSettings(dto.getClientSettings())
                .tokenSettings(dto.getTokenSettings())
                .build();
    }
}
