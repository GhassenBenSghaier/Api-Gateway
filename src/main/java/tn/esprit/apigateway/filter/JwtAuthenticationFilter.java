//package tn.esprit.apigateway.filter;
//
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.Jwts;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.cloud.gateway.filter.GatewayFilter;
//import org.springframework.cloud.gateway.filter.GatewayFilterChain;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.stereotype.Component;
//import org.springframework.web.server.ServerWebExchange;
//import reactor.core.publisher.Mono;
//
//import jakarta.annotation.PostConstruct;
//import javax.crypto.spec.SecretKeySpec;
//import java.util.Base64;
//
//@Component
//public class JwtAuthenticationFilter implements GatewayFilter {
//
//    @Value("${jwt.secret}")
//    private String secretKeyBase64;
//
//    private javax.crypto.SecretKey secretKey;
//
//    @PostConstruct
//    public void init() {
//        if (secretKeyBase64 == null) {
//            throw new IllegalStateException("JWT secret key is not configured. Please set 'jwt.secret' in application.yml");
//        }
//        byte[] keyBytes = Base64.getDecoder().decode(secretKeyBase64);
//        this.secretKey = new SecretKeySpec(keyBytes, "HmacSHA512");
//    }
//
//    @Override
//    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
//        ServerHttpRequest request = exchange.getRequest();
//
//        // Skip authentication for login endpoint
//        if (request.getURI().getPath().contains("/api/auth/login")) {
//            return chain.filter(exchange);
//        }
//
//        String authHeader = request.getHeaders().getFirst("Authorization");
//        if (authHeader != null && authHeader.startsWith("Bearer ")) {
//            String token = authHeader.substring(7);
//            try {
//                Claims claims = Jwts.parserBuilder()
//                        .setSigningKey(secretKey)
//                        .build()
//                        .parseClaimsJws(token)
//                        .getBody();
//                exchange.getRequest().mutate()
//                        .header("X-Authenticated-User", claims.getSubject())
//                        .build();
//                return chain.filter(exchange);
//            } catch (Exception e) {
//                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//                return exchange.getResponse().setComplete();
//            }
//        }
//        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
//        return exchange.getResponse().setComplete();
//    }
//}

package tn.esprit.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class JwtAuthenticationFilter implements GatewayFilter {

    @Value("${jwt.secret}")
    private String secretKeyBase64;

    private javax.crypto.SecretKey secretKey;

    @PostConstruct
    public void init() {
        if (secretKeyBase64 == null) {
            throw new IllegalStateException("JWT secret key is not configured. Please set 'jwt.secret' in application.yml");
        }
        byte[] keyBytes = Base64.getDecoder().decode(secretKeyBase64);
        this.secretKey = new SecretKeySpec(keyBytes, "HmacSHA512");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();


        String path = request.getURI().getPath();
        if (path.contains("/api/auth/login") || path.contains("/api/auth/register")) {
            return chain.filter(exchange);
        }

        String authHeader = request.getHeaders().getFirst("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            try {
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(secretKey)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();
                exchange.getRequest().mutate()
                        .header("X-Authenticated-User", claims.getSubject())
                        .build();
                return chain.filter(exchange);
            } catch (Exception e) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }
        }
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}