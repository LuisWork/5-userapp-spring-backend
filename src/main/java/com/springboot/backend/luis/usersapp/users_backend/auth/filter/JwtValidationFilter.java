package com.springboot.backend.luis.usersapp.users_backend.auth.filter;

import java.io.IOException;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import static com.springboot.backend.luis.usersapp.users_backend.auth.TokenJwtConfig.HEADER_AUTHORIZATION;
import static com.springboot.backend.luis.usersapp.users_backend.auth.TokenJwtConfig.PREFIX_TOKEN;
import static com.springboot.backend.luis.usersapp.users_backend.auth.TokenJwtConfig.SECRET_KEY;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtValidationFilter extends BasicAuthenticationFilter{

    public JwtValidationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
                
                String header = request.getHeader(HEADER_AUTHORIZATION);

                if(header == null || !header.startsWith(PREFIX_TOKEN)) {
                    chain.doFilter(request, response);
                    return;
                }

                String token = header.replace(PREFIX_TOKEN, "");
                

                try{
                    Claims claims = Jwts.parser().verifyWith(SECRET_KEY).build().parseSignedClaims(token).getPayload();
                    String username = claims.getSubject();
                    String username2 = (String) claims.get("username");
                    Object authoritiesClaims = claims.get("authorities");
                }catch(JwtException e) {
                    
                }
                

    }

    

    

}
