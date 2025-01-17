package com.example.userauthservice.security.jwt;

import com.example.userauthservice.config.RSAKeyRecord;
import com.example.userauthservice.repository.RefreshTokenRepo;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class JWTRefreshTokenFilter extends OncePerRequestFilter {

    private  final RSAKeyRecord rsaKeyRecord;
    private final JwtTokenUtils jwtTokenUtils;
    private final RefreshTokenRepo refreshTokenRepo;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        try {
            log.info("[JwtRefreshTokenFilter:doFilterInternal] :: Started ");

            log.info("[JwtRefreshTokenFilter:doFilterInternal]Filtering the Http Request:{}", request.getRequestURI());


            final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);


            if (!authHeader.startsWith("Bearer ")) {
                filterChain.doFilter(request, response);
                return;
            }

            JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaKeyRecord.rsaPublicKey()).build();
//            final String token = getHttpCookie(request,"refresh-token");
            final String token = authHeader.substring(7);
            final Jwt jwtRefreshToken = jwtDecoder.decode(token);


            final String userName = jwtTokenUtils.getUserName(jwtRefreshToken);


            if (!userName.isEmpty() && SecurityContextHolder.getContext().getAuthentication() == null) {
                //Check if refreshToken isPresent in database and is valid
                var isRefreshTokenValidInDatabase = refreshTokenRepo.findByRefreshToken(jwtRefreshToken.getTokenValue())
                        .map(refreshTokenEntity -> !refreshTokenEntity.isRevoked())
                        .orElse(false);

                UserDetails userDetails = jwtTokenUtils.userDetails(userName);
                if (jwtTokenUtils.isTokenValid(jwtRefreshToken, userDetails) && isRefreshTokenValidInDatabase) {
                    SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                    UsernamePasswordAuthenticationToken createdToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );

                    createdToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    securityContext.setAuthentication(createdToken);
                    SecurityContextHolder.setContext(securityContext);
                }
            }
            log.info("[JwtRefreshTokenFilter:doFilterInternal] Completed");
            filterChain.doFilter(request, response);
        }catch (JwtValidationException jwtValidationException){
            log.error("[JwtRefreshTokenFilter:doFilterInternal] Exception due to :{}",jwtValidationException.getMessage());
            throw new ResponseStatusException(HttpStatus.NOT_ACCEPTABLE,jwtValidationException.getMessage());
        }
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
}
