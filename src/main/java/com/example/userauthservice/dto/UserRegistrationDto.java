package com.example.userauthservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserRegistrationDto {
    @NotEmpty(message = "User Name must not be empty")
    String userName;
    String userMobileNo;
    @NotEmpty(message = "User email must not be empty") //Neither null nor 0 size
    @Email(message = "Invalid email format")
    String userEmail;

    @NotEmpty(message = "User password must not be empty")
    String userPassword;
    @NotEmpty(message = "User role must not be empty")
    String userRole;
}
