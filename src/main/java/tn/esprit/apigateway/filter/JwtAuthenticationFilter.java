package tn.esprit.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import jakarta.annotation.PostConstruct;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    @Value("${jwt.secret}")
    private String secretKeyBase64;

    private javax.crypto.SecretKey secretKey;

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    @PostConstruct
    public void init() {
        if (secretKeyBase64 == null) {
            throw new IllegalStateException("JWT secret key is not configured.");
        }
        byte[] keyBytes = Base64.getDecoder().decode(secretKeyBase64);
        this.secretKey = new SecretKeySpec(keyBytes, "HmacSHA512");
        System.out.println("Gateway Filter - Initialized with secret key");
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();
            String method = request.getMethod().toString();
            System.out.println("Gateway Filter - Processing request - Method: " + method + ", Path: " + path);

            // Handle CORS preflight
            if ("OPTIONS".equals(method)) {
                System.out.println("Gateway Filter - Handling OPTIONS request");
                ServerHttpResponse response = exchange.getResponse();
                response.setStatusCode(HttpStatus.OK);
                // Remove manual CORS headers; rely on globalcors
                return response.setComplete();
            }

            if (path.contains("/api/auth/login") || path.contains("/api/auth/register")) {
                System.out.println("Gateway Filter - Bypassing JWT check for: " + path);
                // Remove manual CORS headers; rely on globalcors
                return chain.filter(exchange);
            }

            String authHeader = request.getHeaders().getFirst("Authorization");
            System.out.println("Gateway Filter - Authorization Header: " + authHeader);

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
                    System.out.println("Gateway Filter - Token validated, user: " + claims.getSubject());
                    return chain.filter(exchange);
                } catch (Exception e) {
                    System.out.println("Gateway Filter - JWT Validation Failed: " + e.getMessage());
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }
            }

            System.out.println("Gateway Filter - No valid token found, rejecting with 401");
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        };
    }

    public static class Config {
        // Add configuration properties if needed
    }
}