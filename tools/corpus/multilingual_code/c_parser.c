#include "c_parser.h"
#include <string.h>

ParseStatus lexer_init(LexerContext *ctx, const uint8_t *buf, size_t len) {
    if (!ctx || !buf) {
        return PARSE_STATUS_INVALID_SYNTAX;
    }
    ctx->buffer = buf;
    ctx->length = len;
    ctx->cursor = 0;
    ctx->line_number = 1;
    return PARSE_STATUS_OK;
}

ParseStatus lexer_consume_token(LexerContext *ctx, uint8_t *out_token, size_t max_out, size_t *out_len) {
    if (!ctx || !out_token || !out_len || max_out == 0) {
        return PARSE_STATUS_INVALID_SYNTAX;
    }
    *out_len = 0;

    // Skip whitespace
    while (ctx->cursor < ctx->length) {
        uint8_t c = ctx->buffer[ctx->cursor];
        if (c == '\n') {
            ctx->line_number++;
            ctx->cursor++;
        } else if (c == ' ' || c == '\t' || c == '\r') {
            ctx->cursor++;
        } else {
            break;
        }
    }

    if (ctx->cursor >= ctx->length) {
        return PARSE_STATUS_UNEXPECTED_EOF;
    }

    size_t start = ctx->cursor;
    while (ctx->cursor < ctx->length) {
        uint8_t c = ctx->buffer[ctx->cursor];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            break;
        }
        ctx->cursor++;
    }

    size_t token_size = ctx->cursor - start;
    if (token_size >= max_out) {
        return PARSE_STATUS_BUFFER_OVERFLOW;
    }

    memcpy(out_token, ctx->buffer + start, token_size);
    out_token[token_size] = '\0';
    *out_len = token_size;

    return PARSE_STATUS_OK;
}
