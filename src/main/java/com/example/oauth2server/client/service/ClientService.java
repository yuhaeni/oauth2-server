package com.example.oauth2server.client.service;

import com.example.oauth2server.client.domain.Client;
import com.example.oauth2server.client.repository.CustomRegisteredClientRepository;
import com.example.oauth2server.dto.ClientSaveRequestDto;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

@Service
public class ClientService {

    private final CustomRegisteredClientRepository registeredClientRepository;

    public ClientService(CustomRegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    public void registerClient(ClientSaveRequestDto clientSaveRequestDto){
        Client client = clientSaveRequestDto.toEntity(clientSaveRequestDto);
        RegisteredClient registeredClient = Client.toObject(client);

        registeredClientRepository.save(registeredClient);
    }

}
