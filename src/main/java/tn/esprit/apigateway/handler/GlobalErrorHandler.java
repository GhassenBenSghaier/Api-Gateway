package tn.esprit.apigateway.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;
import reactor.core.publisher.Mono;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.stereotype.Component;

@Component
public class GlobalErrorHandler implements WebExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalErrorHandler.class);

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
        logger.error("Gateway error: {}", ex.getMessage(), ex);
        if (exchange.getResponse().isCommitted()) {
            return Mono.error(ex);
        }
        exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        String errorMessage = "{\"error\":\"" + ex.getMessage() + "\"}";
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(errorMessage.getBytes());
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}