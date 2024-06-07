package com.example.userauthservice.mappers;

import com.example.userauthservice.dto.UserRegistrationDto;
import com.example.userauthservice.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserInfoMapper {

    private final PasswordEncoder passwordEncoder;
    public User convertToEntity(UserRegistrationDto userRegistrationDto) {
        User userInfoEntity = new User();
        userInfoEntity.setUserName(userRegistrationDto.getUserName());
        userInfoEntity.setEmailId(userRegistrationDto.getUserEmail());
        userInfoEntity.setMobileNumber(userRegistrationDto.getUserMobileNo());
        userInfoEntity.setRoles(userRegistrationDto.getUserRole());
        userInfoEntity.setPassword(passwordEncoder.encode(userRegistrationDto.getUserPassword()));
        return userInfoEntity;
    }
}