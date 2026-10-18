#ifndef C_PARSER_H
#define C_PARSER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PARSE_STATUS_OK = 0,
    PARSE_STATUS_INVALID_SYNTAX = 1,
    PARSE_STATUS_BUFFER_OVERFLOW = 2,
    PARSE_STATUS_UNEXPECTED_EOF = 3
} ParseStatus;

typedef struct {
    const uint8_t *buffer;
    size_t length;
    size_t cursor;
    uint32_t line_number;
} LexerContext;

ParseStatus lexer_init(LexerContext *ctx, const uint8_t *buf, size_t len);
ParseStatus lexer_consume_token(LexerContext *ctx, uint8_t *out_token, size_t max_out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* C_PARSER_H */
