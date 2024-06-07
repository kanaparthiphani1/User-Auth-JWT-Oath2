package com.example.userauthservice.service;

import com.example.userauthservice.dto.AuthResponseDto;
import com.example.userauthservice.dto.TokenType;
import com.example.userauthservice.dto.UserRegistrationDto;
import com.example.userauthservice.mappers.UserInfoMapper;
import com.example.userauthservice.model.RefreshTokenEntity;
import com.example.userauthservice.model.User;
import com.example.userauthservice.repository.RefreshTokenRepo;
import com.example.userauthservice.repository.UserRepo;
import com.example.userauthservice.security.jwt.JwtTokenGenerator;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepo userRepo;

    private final JwtTokenGenerator jwtTokenGenerator;

    private final RefreshTokenRepo refreshTokenRepo;

    private final UserInfoMapper userInfoMapper;


    public AuthResponseDto getJwtTokensAfterAuthentication(Authentication authentication,  HttpServletResponse httpResp) {
        try
        {
            User user = userRepo.findByEmailId(authentication.getName())
                    .orElseThrow(()-> new ResponseStatusException(HttpStatus.NOT_FOUND,"USER NOT FOUND "));


            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);
            saveUserRefreshToken(user,refreshToken);

            creatRefreshTokenCookie(httpResp,refreshToken);

            return  AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(15 * 60)
                    .userName(user.getUserName())
                    .tokenType(TokenType.Bearer)
                    .build();


        }catch (Exception e){
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Please Try Again");
        }
    }

    public Object getAccessTokenUsingRefreshToken(HttpServletRequest req) {

        final String refreshToken = getHttpCookie(req,"refresh_token");

        //Find refreshToken from database and should not be revoked : Same thing can be done through filter.
        RefreshTokenEntity refreshTokenEntity = refreshTokenRepo.findByRefreshToken(refreshToken)
                .filter(tokens-> !tokens.isRevoked())
                .orElseThrow(()-> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,"Refresh token revoked"));

        User user = refreshTokenEntity.getUser();

        //Now create the Authentication object
        Authentication authentication =  createAuthenticationObject(user);

        //Use the authentication object to generate new accessToken as the Authentication object that we will have may not contain correct role.
        String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

        return  AuthResponseDto.builder()
                .accessToken(accessToken)
                .accessTokenExpiry(5 * 60)
                .userName(user.getUserName())
                .tokenType(TokenType.Bearer)
                .build();
    }

    public String getHttpCookie(HttpServletRequest req, String headerName){
        Cookie[] cookies = req.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals("refresh_token")) {
                return cookie.getValue();
            }
        }
        return "";
    }

    private static Authentication createAuthenticationObject(User user) {
        // Extract user details from UserDetailsEntity
        String username = user.getEmailId();
        String password = user.getPassword();
        String roles = user.getRoles();

        // Extract authorities from roles (comma-separated)
        String[] roleArray = roles.split(",");
        GrantedAuthority[] authorities = Arrays.stream(roleArray)
                .map(role -> (GrantedAuthority) role::trim)
                .toArray(GrantedAuthority[]::new);

        return new UsernamePasswordAuthenticationToken(username, password, Arrays.asList(authorities));
    }

    private void saveUserRefreshToken(User user, String refreshToken) {
        RefreshTokenEntity refreshTokenEntity = RefreshTokenEntity.builder()
                .user(user)
                .refreshToken(refreshToken)
                .revoked(false)
                .build();
        refreshTokenRepo.save(refreshTokenEntity);
    }

    public AuthResponseDto registerUser(UserRegistrationDto userRegistrationDto, HttpServletResponse httpServletResponse){

        try{

            Optional<User> user = userRepo.findByEmailId(userRegistrationDto.getUserEmail());
            if(user.isPresent()){
                throw new Exception("User Already Exist");
            }

            User userObj = userInfoMapper.convertToEntity(userRegistrationDto);
            Authentication authentication = createAuthenticationObject(userObj);


            // Generate a JWT token
            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            User savedUserDetails = userRepo.save(userObj);
            saveUserRefreshToken(userObj,refreshToken);

            creatRefreshTokenCookie(httpServletResponse,refreshToken);

            return   AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(5 * 60)
                    .userName(savedUserDetails.getUserName())
                    .tokenType(TokenType.Bearer)
                    .build();


        }catch (Exception e){
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,e.getMessage());
        }

    }

    private void creatRefreshTokenCookie(HttpServletResponse httpResp, String refreshToken) {
        Cookie refreshTokenCookie = new Cookie("refresh_token",refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setMaxAge(15 * 24 * 60 * 60 );
        refreshTokenCookie.setDomain("");
        refreshTokenCookie.setPath("/");
        httpResp.addCookie(refreshTokenCookie);
    }
}
