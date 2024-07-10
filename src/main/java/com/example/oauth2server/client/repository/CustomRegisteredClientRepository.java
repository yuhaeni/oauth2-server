package com.example.oauth2server.client.repository;

import com.example.oauth2server.client.domain.Client;
import com.example.oauth2server.client.domain.ClientRepository;
import com.example.oauth2server.dto.ClientSaveRequestDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CustomRegisteredClientRepository implements RegisteredClientRepository {

    private final ClientRepository clientRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        ClientSaveRequestDto clientSaveRequestDto = new ClientSaveRequestDto();
        Client client = clientSaveRequestDto.toEntity(registeredClient);
        clientRepository.save(client);
    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = clientRepository.findById(id).orElseThrow();
        return Client.toObject(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepository.findByClientEmail(clientId);
        return Client.toObject(client);
    }

}
