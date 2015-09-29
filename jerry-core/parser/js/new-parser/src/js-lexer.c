/* Copyright 2015 University of Szeged.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "js-parser-defines.h"

#define UTF8_INTERMEDIATE_OCTET_MASK 0xc0
#define UTF8_INTERMEDIATE_OCTET 0x80

/**
 * Align column to the next tab position.
 *
 * @return aligned position
 */
static size_t
align_column_to_tab (size_t column) /**< current column */
{
  /* Tab aligns to zero column start position. */
  return (((column - 1) + 8) & ~0x7) + 1;
} /* align_column_to_tab */

/**
 * Parse hexadecimal character sequence
 *
 * @return character value
 */
static lexer_character_type
lexer_hex_to_character (parser_context *context_p, /**< context */
                        const uint8_t *source_p, /**< current source position */
                        int length)
{
  lexer_character_type result;

  do
  {
    uint8_t byte = *source_p++;

    result <<= 4;

    if (byte >= '0' && byte <= '9')
    {
      result += byte - '0';
    }
    else
    {
      byte |= 0x20;
      if (byte >= 'a' && byte <= 'f')
      {
        result += byte - ('a' - 10);
      }
      else
      {
        parser_raise_error (context_p, "Invalid escape sequence.");
      }
    }
  }
  while (--length > 0);

  return result;
} /* lexer_hex_to_character */

/**
 * Skip space mode
 */
typedef enum
{
  LEXER_SKIP_SPACES,                 /**< skip spaces mode */
  LEXER_SKIP_SINGLE_LINE_COMMENT,    /**< parse single line comment */
  LEXER_SKIP_MULTI_LINE_COMMENT,     /**< parse multi line comment */
} skip_mode;

/**
 * Skip spaces.
 */
static void
skip_spaces (parser_context *context_p) /**< context */
{
  skip_mode mode = LEXER_SKIP_SPACES;
  const uint8_t *source_end_p = context_p->source_end_p;

  context_p->token.was_newline = 0;

  while (1)
  {
    if (context_p->source_p >= source_end_p)
    {
      if (mode == LEXER_SKIP_MULTI_LINE_COMMENT)
      {
        parser_raise_error (context_p, "Unterminated /* multiline comment.");
      }
      return;
    }

    switch (context_p->source_p[0])
    {
      case LEXER_NEWLINE_CR:
      {
        if (context_p->source_p + 1 < source_end_p
            && context_p->source_p[1] == LEXER_NEWLINE_LF)
        {
          context_p->source_p++;
        }
        /* FALLTHRU */
      }

      case LEXER_NEWLINE_LF:
      {
        context_p->line++;
        context_p->column = 0;
        context_p->token.was_newline = 1;

        if (mode == LEXER_SKIP_SINGLE_LINE_COMMENT)
        {
          mode = LEXER_SKIP_SPACES;
        }
        /* FALLTHRU */
      }

      case 0x0b:
      case 0x0c:
      case 0x20:
      {
        context_p->source_p++;
        context_p->column++;
        continue;
        /* FALLTHRU */
      }

      case LEXER_TAB:
      {
        context_p->column = align_column_to_tab (context_p->column);
        context_p->source_p++;
        continue;
        /* FALLTHRU */
      }

      case '/':
      {
        if (mode == LEXER_SKIP_SPACES
            && context_p->source_p + 1 < source_end_p)
        {
          if (context_p->source_p[1] == '/')
          {
            mode = LEXER_SKIP_SINGLE_LINE_COMMENT;
          }
          else if (context_p->source_p[1] == '*')
          {
            mode = LEXER_SKIP_MULTI_LINE_COMMENT;
            context_p->token.line = context_p->line;
            context_p->token.column = context_p->column;
          }

          if (mode != LEXER_SKIP_SPACES)
          {
            context_p->source_p += 2;
            context_p->column += 2;
            continue;
          }
        }
        break;
      }

      case '*':
      {
        if (mode == LEXER_SKIP_MULTI_LINE_COMMENT
            && context_p->source_p + 1 < source_end_p
            && context_p->source_p[1] == '/')
        {
          mode = LEXER_SKIP_SPACES;
          context_p->source_p += 2;
          context_p->column += 2;
          continue;
        }
        break;
      }

      case 0xc2:
      {
        if (context_p->source_p + 1 < source_end_p
            && context_p->source_p[1] == 0xa0)
        {
          /* Codepoint \u00A0 */
          context_p->source_p += 2;
          context_p->column++;
          continue;
        }
        break;
      }

      case LEXER_NEWLINE_LS_PS_BYTE_1:
      {
        PARSER_ASSERT (context_p->source_p + 2 < source_end_p);
        if (LEXER_NEWLINE_LS_PS_BYTE_23 (context_p->source_p))
        {
          /* Codepoint \u2028 and \u2029 */
          context_p->line++;
          context_p->column = 1;
          context_p->token.was_newline = 1;

          if (mode == LEXER_SKIP_SINGLE_LINE_COMMENT)
          {
            mode = LEXER_SKIP_SPACES;
          }
          continue;
        }
        break;
      }

      case 0xef:
      {
        if (context_p->source_p + 2 < source_end_p
            && context_p->source_p[1] == 0xbb
            && context_p->source_p[2] == 0xbf)
        {
          /* Codepoint \uFEFF */
          context_p->source_p += 2;
          context_p->column++;
          continue;
        }
        break;
      }

      default:
      {
        break;
      }
    }

    if (mode == LEXER_SKIP_SPACES)
    {
      return;
    }

    context_p->source_p ++;
    if ((context_p->source_p[0] & UTF8_INTERMEDIATE_OCTET_MASK) != UTF8_INTERMEDIATE_OCTET)
    {
      context_p->column++;
    }
  }
}

/**
 * Keyword data.
 */
typedef struct
{
  const uint8_t *keyword_p;     /**< keyword string */
  lexer_token_type type;        /**< keyword token type */
} keyword_string;

#define LEXER_KEYWORD(name, type) { (const uint8_t *) (name), (type) }
#define LEXER_KEYWORD_END()       { (const uint8_t *) NULL, LEXER_EOS }

static const keyword_string keyword_length_2[4] =
{
  LEXER_KEYWORD ("do", LEXER_KEYW_DO),
  LEXER_KEYWORD ("if", LEXER_KEYW_IF),
  LEXER_KEYWORD ("in", LEXER_KEYW_IN),
  LEXER_KEYWORD_END ()
};

static const keyword_string keyword_length_3[6] =
{
  LEXER_KEYWORD ("for", LEXER_KEYW_FOR),
  LEXER_KEYWORD ("let", LEXER_KEYW_LET),
  LEXER_KEYWORD ("new", LEXER_KEYW_NEW),
  LEXER_KEYWORD ("try", LEXER_KEYW_TRY),
  LEXER_KEYWORD ("var", LEXER_KEYW_VAR),
  LEXER_KEYWORD_END ()
};

static const keyword_string keyword_length_4[9] =
{
  LEXER_KEYWORD ("case", LEXER_KEYW_CASE),
  LEXER_KEYWORD ("else", LEXER_KEYW_ELSE),
  LEXER_KEYWORD ("enum", LEXER_KEYW_ENUM),
  LEXER_KEYWORD ("null", LEXER_LIT_NULL),
  LEXER_KEYWORD ("this", LEXER_KEYW_THIS),
  LEXER_KEYWORD ("true", LEXER_LIT_TRUE),
  LEXER_KEYWORD ("void", LEXER_KEYW_VOID),
  LEXER_KEYWORD ("with", LEXER_KEYW_WITH),
  LEXER_KEYWORD_END ()
};

static const keyword_string keyword_length_5[10] =
{
  LEXER_KEYWORD ("break", LEXER_KEYW_BREAK),
  LEXER_KEYWORD ("catch", LEXER_KEYW_CATCH),
  LEXER_KEYWORD ("class", LEXER_KEYW_CLASS),
  LEXER_KEYWORD ("const", LEXER_KEYW_CONST),
  LEXER_KEYWORD ("false", LEXER_LIT_FALSE),
  LEXER_KEYWORD ("super", LEXER_KEYW_SUPER),
  LEXER_KEYWORD ("throw", LEXER_KEYW_THROW),
  LEXER_KEYWORD ("while", LEXER_KEYW_WHILE),
  LEXER_KEYWORD ("yield", LEXER_KEYW_YIELD),
  LEXER_KEYWORD_END ()
};

static const keyword_string keyword_length_6[9] =
{
  LEXER_KEYWORD ("delete", LEXER_KEYW_DELETE),
  LEXER_KEYWORD ("export", LEXER_KEYW_EXPORT),
  LEXER_KEYWORD ("import", LEXER_KEYW_IMPORT),
  LEXER_KEYWORD ("public", LEXER_KEYW_PUBLIC),
  LEXER_KEYWORD ("return", LEXER_KEYW_RETURN),
  LEXER_KEYWORD ("static", LEXER_KEYW_STATIC),
  LEXER_KEYWORD ("switch", LEXER_KEYW_SWITCH),
  LEXER_KEYWORD ("typeof", LEXER_KEYW_TYPEOF),
  LEXER_KEYWORD_END ()
};

static const keyword_string keyword_length_7[6] =
{
  LEXER_KEYWORD ("default", LEXER_KEYW_DEFAULT),
  LEXER_KEYWORD ("extends", LEXER_KEYW_EXTENDS),
  LEXER_KEYWORD ("finally", LEXER_KEYW_FINALLY),
  LEXER_KEYWORD ("private", LEXER_KEYW_PRIVATE),
  LEXER_KEYWORD ("package", LEXER_KEYW_PACKAGE),
  LEXER_KEYWORD_END ()
};

static const keyword_string keyword_length_8[4] =
{
  LEXER_KEYWORD ("continue", LEXER_KEYW_CONTINUE),
  LEXER_KEYWORD ("debugger", LEXER_KEYW_DEBUGGER),
  LEXER_KEYWORD ("function", LEXER_KEYW_FUNCTION),
  LEXER_KEYWORD_END ()
};

static const keyword_string keyword_length_9[3] =
{
  LEXER_KEYWORD ("interface", LEXER_KEYW_INTERFACE),
  LEXER_KEYWORD ("protected", LEXER_KEYW_PROTECTED),
  LEXER_KEYWORD_END ()
};

static const keyword_string keyword_length_10[3] =
{
  LEXER_KEYWORD ("instanceof", LEXER_KEYW_INSTANCEOF),
  LEXER_KEYWORD ("implements", LEXER_KEYW_IMPLEMENTS),
  LEXER_KEYWORD_END ()
};

static const keyword_string * const keyword_string_list[9] =
{
  keyword_length_2,
  keyword_length_3,
  keyword_length_4,
  keyword_length_5,
  keyword_length_6,
  keyword_length_7,
  keyword_length_8,
  keyword_length_9,
  keyword_length_10
};

#undef LEXER_KEYWORD
#undef LEXER_KEYWORD_END

/**
 * Parse identifier.
 */
static void
lexer_parser_identifier (parser_context *context_p, /**< context */
                         int check_keywords) /**< check keywords */
{
  /* Only very few identifiers contains \u escape sequences. */
  const uint8_t *source_p = context_p->source_p;
  const uint8_t *ident_start_p = context_p->source_p;
  /* Note: newline or tab cannot be part of an identifier. */
  size_t column = context_p->column;
  const uint8_t *source_end_p = context_p->source_end_p;
  size_t length = 0;

  context_p->token.type = LEXER_LITERAL;
  context_p->token.literal_type = LEXER_IDENT_LITERAL;
  context_p->token.literal_index = PARSER_MAXIMUM_NUMBER_OF_LITERALS + 1;
  context_p->token.char_literal.type = LEXER_IDENT_LITERAL;
  context_p->token.char_literal.has_escape = 0;

  do
  {
    if (*source_p == '\\')
    {
      uint16_t character;

      context_p->token.char_literal.has_escape = 1;
      context_p->source_p = source_p;
      context_p->token.column = column;

      if ((source_p + 6 > source_end_p) || (source_p[1] != 'u'))
      {
        parser_raise_error (context_p, "Valid unicode escape sequence expected.");
      }

      character = lexer_hex_to_character (context_p, source_p + 2, 4);

      if (length == 0)
      {
        if (!util_is_identifier_start_character (character))
        {
          parser_raise_error (context_p, "Character cannot be start of an identifier.");
        }
      }
      else
      {
        if (!util_is_identifier_part_character (character))
        {
          parser_raise_error (context_p, "Character cannot be part of an identifier.");
        }
      }

      length += util_get_utf8_length (character);
      source_p += 6;
      column += 6;
      continue;
    }

    /* Valid identifiers cannot contain 4 byte long utf-8
     * characters, since those characters are represented
     * by 2 ecmascript (UTF-16) characters, and those
     * characters cannot be literal characters. */
    PARSER_ASSERT (source_p[0] < LEXER_UTF8_4BYTE_START);

    source_p++;
    length++;
    column++;
    while ((source_p[0] & UTF8_INTERMEDIATE_OCTET_MASK) == UTF8_INTERMEDIATE_OCTET)
    {
      source_p++;
      length++;
    }
  }
  while (source_p < source_end_p
         && (util_is_identifier_part (source_p) || *source_p == '\\'));

  context_p->source_p = ident_start_p;
  context_p->token.column = context_p->column;

  if (length > PARSER_MAXIMUM_IDENT_LENGTH)
  {
    parser_raise_error (context_p, "Identifier too long.");
  }

  /* Check keywords (Only if there is no \u escape sequence in the pattern). */
  if (check_keywords
      && !context_p->token.char_literal.has_escape
      && (length >= 2 && length <= 10))
  {
    const keyword_string *keyword_p = keyword_string_list[length - 2];

    do
    {
      if ((keyword_p->type < LEXER_FIRST_FUTURE_STRICT_RESERVED_WORD || context_p->is_strict)
          && ident_start_p[0] == keyword_p->keyword_p[0]
          && ident_start_p[1] == keyword_p->keyword_p[1]
          && memcmp (ident_start_p, keyword_p->keyword_p, length) == 0)
      {
        context_p->token.type = keyword_p->type;
        break;
      }
      keyword_p++;
    }
    while (keyword_p->type != LEXER_EOS);
  }

  if (context_p->token.type == LEXER_LITERAL)
  {
    /* Fill literal data. */
    context_p->token.char_literal.char_p = ident_start_p;
    context_p->token.char_literal.length = length;
  }

  context_p->source_p = source_p;
  context_p->column = column;
} /* lexer_parser_identifier */

/**
 * Parse string without escape sequences.
 */
static void
lexer_parse_string (parser_context *context_p) /**< context */
{
  uint8_t str_end_character = context_p->source_p[0];
  const uint8_t *source_p = context_p->source_p + 1;
  const uint8_t *string_start_p = source_p;
  const uint8_t *source_end_p = context_p->source_end_p;
  size_t line = context_p->line;
  size_t column = context_p->column + 1;
  size_t original_line = line;
  size_t original_column = column;
  size_t length = 0;
  int has_escape = 0;

  while (1)
  {
    if (source_p >= source_end_p)
    {
      context_p->token.line = original_line;
      context_p->token.column = original_column - 1;
      parser_raise_error (context_p, "Unterminated string literal.");
    }

    if (*source_p == str_end_character)
    {
      break;
    }

    if (*source_p == '\\')
    {
      source_p++;
      column++;
      if (source_p >= source_end_p)
      {
        /* Will throw an unterminated string error. */
        continue;
      }

      has_escape = 1;

      /* Newline is ignored. */
      if (*source_p == LEXER_NEWLINE_CR
          || *source_p == LEXER_NEWLINE_LF
          || (*source_p == LEXER_NEWLINE_LS_PS_BYTE_1 && LEXER_NEWLINE_LS_PS_BYTE_23 (source_p)))
      {
        source_p += (*source_p == LEXER_NEWLINE_LS_PS_BYTE_1) ? 3 : 1;
        line++;
        column = 1;
        continue;
      }

      /* Except \x and \u, everything is converted to
       * a character which has the same byte length. */
      if (*source_p == 'x' || *source_p == 'u')
      {
        int hex_part_length = (*source_p == 'x') ? 2 : 4;

        context_p->token.line = line;
        context_p->token.column = column - 1;
        if (source_p + 1 + hex_part_length > source_end_p)
        {
          parser_raise_error (context_p, "Invalid escape sequence.");
        }

        length += util_get_utf8_length (lexer_hex_to_character (context_p,
                                                                source_p + 1,
                                                                hex_part_length));
        source_p += hex_part_length + 1;
        column += hex_part_length + 1;
        continue;
      }
    }

    if (*source_p >= LEXER_UTF8_4BYTE_START)
    {
      /* Processing 4 byte unicode sequence (even if it is
       * after a backslash). Always converted to two 3 byte
       * long sequence. */
      length += 2 * 3;
      has_escape = 1;
      source_p += 4;
      column++;
      continue;
    }
    else if (*source_p == LEXER_NEWLINE_CR
             || *source_p == LEXER_NEWLINE_LF
             || (*source_p == LEXER_NEWLINE_LS_PS_BYTE_1 && LEXER_NEWLINE_LS_PS_BYTE_23 (source_p)))
    {
      context_p->token.line = line;
      context_p->token.column = column;
      parser_raise_error (context_p, "Newline is not allowed in string.");
    }
    else if (*source_p == LEXER_TAB)
    {
      /* Subtract -1 because column is increased below. */
      column = align_column_to_tab (column) - 1;
    }

    source_p++;
    column++;
    length++;
    while ((*source_p & UTF8_INTERMEDIATE_OCTET_MASK) == UTF8_INTERMEDIATE_OCTET)
    {
      source_p++;
      length++;
    }
  }

  if (length > PARSER_MAXIMUM_STRING_LENGTH)
  {
    parser_raise_error (context_p, "String too long.");
  }

  context_p->token.type = LEXER_LITERAL;
  context_p->token.literal_type = LEXER_STRING_LITERAL;
  context_p->token.literal_index = PARSER_MAXIMUM_NUMBER_OF_LITERALS + 1;

  /* Fill literal data. */
  context_p->token.char_literal.char_p = string_start_p;
  context_p->token.char_literal.length = length;
  context_p->token.char_literal.type = LEXER_STRING_LITERAL;
  context_p->token.char_literal.has_escape = has_escape;

  context_p->source_p = source_p + 1;
  context_p->line = line;
  context_p->column = column + 1;
} /* lexer_parse_string */

#define LEXER_TYPE_A_TOKEN(char1, type1) \
  case (uint8_t) (char1) : \
  { \
    context_p->token.type = (type1); \
    length = 1; \
    break; \
  }

#define LEXER_TYPE_B_TOKEN(char1, type1, char2, type2) \
  case (uint8_t) (char1) : \
  { \
    if (length >= 2 && context_p->source_p[1] == (uint8_t) (char2)) \
    { \
      context_p->token.type = (type2); \
      length = 2; \
      break; \
    } \
    \
    context_p->token.type = (type1); \
    length = 1; \
    break; \
  }

#define LEXER_TYPE_C_TOKEN(char1, type1, char2, type2, char3, type3) \
  case (uint8_t) (char1) : \
  { \
    if (length >= 2) \
    { \
      if (context_p->source_p[1] == (uint8_t) (char2)) \
      { \
        context_p->token.type = (type2); \
        length = 2; \
        break; \
      } \
      \
      if (context_p->source_p[1] == (uint8_t) (char3)) \
      { \
        context_p->token.type = (type3); \
        length = 2; \
        break; \
      } \
    } \
    \
    context_p->token.type = (type1); \
    length = 1; \
    break; \
  }

#define LEXER_TYPE_D_TOKEN(char1, type1, char2, type2, char3, type3) \
  case (uint8_t) (char1) : \
  { \
    if (length >= 2 && context_p->source_p[1] == (uint8_t) (char2)) \
    { \
      if (length >= 3 && context_p->source_p[2] == (uint8_t) (char3)) \
      { \
        context_p->token.type = (type3); \
        length = 3; \
        break; \
      } \
      \
      context_p->token.type = (type2); \
      length = 2; \
      break; \
    } \
    \
    context_p->token.type = (type1); \
    length = 1; \
    break; \
  }

/**
 * Get next token.
 */
void
lexer_next_token (parser_context *context_p) /**< context */
{
  size_t length;

  skip_spaces (context_p);

  context_p->token.line = context_p->line;
  context_p->token.column = context_p->column;

  length = context_p->source_end_p - context_p->source_p;
  if (length == 0)
  {
    context_p->token.type = LEXER_EOS;
    return;
  }

  if (util_is_identifier_start (context_p->source_p)
      || context_p->source_p[0] == '\\')
  {
    lexer_parser_identifier (context_p, 1);
    return;
  }

  switch (context_p->source_p[0])
  {
    LEXER_TYPE_A_TOKEN ('{', LEXER_LEFT_BRACE);
    LEXER_TYPE_A_TOKEN ('(', LEXER_LEFT_PAREN);
    LEXER_TYPE_A_TOKEN ('[', LEXER_LEFT_SQUARE);
    LEXER_TYPE_A_TOKEN ('}', LEXER_RIGHT_BRACE);
    LEXER_TYPE_A_TOKEN (')', LEXER_RIGHT_PAREN);
    LEXER_TYPE_A_TOKEN (']', LEXER_RIGHT_SQUARE);
    LEXER_TYPE_A_TOKEN ('.', LEXER_DOT);
    LEXER_TYPE_A_TOKEN (';', LEXER_SEMICOLON);
    LEXER_TYPE_A_TOKEN (',', LEXER_COMMA);

    case (uint8_t) '<':
    {
      if (length >= 2)
      {
        if (context_p->source_p[1] == (uint8_t) '=')
        {
          context_p->token.type = LEXER_LESS_EQUAL;
          length = 2;
          break;
        }

        if (context_p->source_p[1] == (uint8_t) '<')
        {
          if (length >= 3 && context_p->source_p[2] == (uint8_t) '=')
          {
            context_p->token.type = LEXER_ASSIGN_LEFT_SHIFT;
            length = 3;
            break;
          }

          context_p->token.type = LEXER_LEFT_SHIFT;
          length = 2;
          break;
        }
      }

      context_p->token.type = LEXER_LESS;
      length = 1;
      break;
    }

    case '>':
    {
      if (length >= 2)
      {
        if (context_p->source_p[1] == (uint8_t) '=')
        {
          context_p->token.type = LEXER_GREATER_EQUAL;
          length = 2;
          break;
        }

        if (context_p->source_p[1] == (uint8_t) '>')
        {
          if (length >= 3)
          {
            if (context_p->source_p[2] == (uint8_t) '=')
            {
              context_p->token.type = LEXER_ASSIGN_RIGHT_SHIFT;
              length = 3;
              break;
            }

            if (context_p->source_p[2] == (uint8_t) '>')
            {
              if (length >= 4 && context_p->source_p[3] == (uint8_t) '=')
              {
                context_p->token.type = LEXER_ASSIGN_UNS_RIGHT_SHIFT;
                length = 4;
                break;
              }

              context_p->token.type = LEXER_UNS_RIGHT_SHIFT;
              length = 3;
              break;
            }
          }

          context_p->token.type = LEXER_RIGHT_SHIFT;
          length = 2;
          break;
        }
      }

      context_p->token.type = LEXER_GREATER;
      length = 1;
      break;
    }

    LEXER_TYPE_D_TOKEN ('=', LEXER_ASSIGN, '=', LEXER_EQUAL, '=', LEXER_STRICT_EQUAL)
    LEXER_TYPE_D_TOKEN ('!', LEXER_LOGICAL_NOT, '=', LEXER_NOT_EQUAL, '=', LEXER_STRICT_NOT_EQUAL)

    LEXER_TYPE_C_TOKEN ('+', LEXER_BINARY_ADD, '=', LEXER_ASSIGN_ADD, '+', LEXER_INCREASE)
    LEXER_TYPE_C_TOKEN ('-', LEXER_BINARY_SUBTRACT, '=', LEXER_ASSIGN_SUBTRACT, '-', LEXER_DECREASE)

    LEXER_TYPE_B_TOKEN ('*', LEXER_MULTIPLY, '=', LEXER_ASSIGN_MULTIPLY)
    LEXER_TYPE_B_TOKEN ('/', LEXER_DIVIDE, '=', LEXER_ASSIGN_DIVIDE)
    LEXER_TYPE_B_TOKEN ('%', LEXER_MODULO, '=', LEXER_ASSIGN_MODULO)

    LEXER_TYPE_C_TOKEN ('&', LEXER_BIT_AND, '=', LEXER_ASSIGN_BIT_AND, '&', LEXER_LOGICAL_AND)
    LEXER_TYPE_C_TOKEN ('|', LEXER_BIT_OR, '=', LEXER_ASSIGN_BIT_OR, '|', LEXER_LOGICAL_OR)

    LEXER_TYPE_B_TOKEN ('^', LEXER_BIT_XOR, '=', LEXER_ASSIGN_BIT_XOR)

    LEXER_TYPE_A_TOKEN ('~', LEXER_BIT_NOT);
    LEXER_TYPE_A_TOKEN ('?', LEXER_QUESTION_MARK);
    LEXER_TYPE_A_TOKEN (':', LEXER_COLON);

    case '\'':
    case '"':
    {
      lexer_parse_string (context_p);
      return;
    }

    default:
    {
      parser_raise_error (context_p, "Invalid character.");
    }
  }

  context_p->source_p += length;
  context_p->column += length;
} /* lexer_next_token */

#undef LEXER_TYPE_A_TOKEN
#undef LEXER_TYPE_B_TOKEN
#undef LEXER_TYPE_C_TOKEN
#undef LEXER_TYPE_D_TOKEN

/**
 * Search or append the string to the literal pool.
 */
static void
lexer_process_char_literal (parser_context *context_p, /**< context */
                            const uint8_t *char_p, /**< characters */
                            size_t length, /**< length of string */
                            uint8_t literal_type) /**< final literal type */
{
  parser_list_iterator literal_iterator;
  lexer_literal *literal_p;
  uint32_t literal_index = 0;
  uint8_t literal_compare_type;

  PARSER_ASSERT (literal_type == LEXER_VAR_LITERAL
                 || literal_type == LEXER_IDENT_LITERAL
                 || literal_type == LEXER_STRING_LITERAL);

  PARSER_ASSERT (literal_type != LEXER_VAR_LITERAL || length <= PARSER_MAXIMUM_IDENT_LENGTH);
  PARSER_ASSERT (literal_type != LEXER_IDENT_LITERAL || length <= PARSER_MAXIMUM_IDENT_LENGTH);
  PARSER_ASSERT (literal_type != LEXER_STRING_LITERAL || length <= PARSER_MAXIMUM_STRING_LENGTH);

  literal_compare_type = (literal_type | 0x1);
  parser_list_iterator_init (&context_p->literal_pool, &literal_iterator);

  while ((literal_p = (lexer_literal *) parser_list_iterator_next (&literal_iterator)) != NULL)
  {
    if ((literal_p->type | 0x1) == literal_compare_type
        && literal_p->length == length
        && util_compare_char_literals (literal_p, char_p))
    {
      if (literal_type == LEXER_VAR_LITERAL && literal_p->type == LEXER_IDENT_LITERAL)
      {
        literal_p->type = LEXER_VAR_LITERAL;
        context_p->ident_count--;
        context_p->var_count++;
        if (context_p->var_count > PARSER_MAXIMUM_NUMBER_OF_VAR_IDENTIFIERS)
        {
          parser_raise_error (context_p, "Maximum number of local variables reached.");
        }
      }
      context_p->token.literal_index = (uint16_t) literal_index;
      context_p->token.literal_type = literal_type;
      return;
    }
    literal_index++;
  }

  if (literal_index >= PARSER_MAXIMUM_NUMBER_OF_LITERALS)
  {
    parser_raise_error (context_p, "Maximum number of literals reached.");
  }

  literal_p = (lexer_literal *) parser_list_append (context_p, &context_p->literal_pool);
  literal_p->length = (uint16_t) length;
  literal_p->type = literal_type;

  if (util_set_char_literal (literal_p, char_p))
  {
    parser_raise_error (context_p, "Out of memory.");
  }

  context_p->token.literal_index = (uint16_t) literal_index;
  context_p->token.literal_type = literal_type;

  switch (literal_type)
  {
    case LEXER_VAR_LITERAL:
    {
      context_p->var_count++;
      if (context_p->var_count > PARSER_MAXIMUM_NUMBER_OF_VAR_IDENTIFIERS)
      {
        parser_raise_error (context_p, "Maximum number of local variables reached.");
      }
      break;
    }
    case LEXER_IDENT_LITERAL:
    {
      context_p->ident_count++;
      break;
    }
    default:
    {
      context_p->other_count++;
      break;
    }
  }
} /* lexer_process_char_literal */

/* Maximum buffer size for identifiers which contains escape sequences. */
#define LEXER_MAX_LITERAL_LOCAL_BUFFER_SIZE 48

/**
 * Construct a literal object from an identifier.
 */
void
lexer_construct_literal_object (parser_context *context_p, /**< context */
                                lexer_char_literal *literal_p, /**< literal token */
                                uint8_t literal_type) /**< final literal type */
{
  uint8_t *destination_start_p;
  uint8_t *destination_p;
  const uint8_t *source_p;
  uint8_t local_byte_array[LEXER_MAX_LITERAL_LOCAL_BUFFER_SIZE];

  PARSER_ASSERT (literal_p->type == LEXER_IDENT_LITERAL
                 || literal_p->type == LEXER_STRING_LITERAL);

  destination_start_p = local_byte_array;
  source_p = literal_p->char_p;

  if (literal_p->has_escape)
  {
    if (literal_p->length > LEXER_MAX_LITERAL_LOCAL_BUFFER_SIZE)
    {
      /* Since syntax checking is done, there cannot be any error after this point. */
      destination_start_p = (uint8_t *) parser_malloc_local (context_p, literal_p->length);
    }

    destination_p = destination_start_p;

    if (literal_p->type == LEXER_IDENT_LITERAL)
    {
      const uint8_t *source_end_p = context_p->source_end_p;

      PARSER_ASSERT (literal_p->length <= PARSER_MAXIMUM_IDENT_LENGTH);

      do
      {
        if (*source_p == '\\')
        {
          destination_p += util_to_utf8_bytes (destination_p,
                                               lexer_hex_to_character (context_p, source_p + 2, 4));
          source_p += 6;
          continue;
        }

        *destination_p++ = *source_p++;
        while ((*source_p & UTF8_INTERMEDIATE_OCTET_MASK) == UTF8_INTERMEDIATE_OCTET)
        {
          *destination_p++ = *source_p++;
        }
      }
      while ((source_p < source_end_p) && (util_is_identifier_part (source_p) || *source_p == '\\'));

      PARSER_ASSERT (destination_p == destination_start_p + literal_p->length);
    }
    else
    {
      uint8_t str_end_character = source_p[-1];

      PARSER_ASSERT (literal_p->length <= PARSER_MAXIMUM_STRING_LENGTH);

      while (1)
      {
        if (*source_p == str_end_character)
        {
          break;
        }

        if (*source_p == '\\')
        {
          uint8_t conv_character;

          source_p++;
          PARSER_ASSERT (source_p < context_p->source_end_p);

          /* Newline is ignored. */
          if (*source_p == LEXER_NEWLINE_CR
              || *source_p == LEXER_NEWLINE_LF
              || (*source_p == LEXER_NEWLINE_LS_PS_BYTE_1 && LEXER_NEWLINE_LS_PS_BYTE_23 (source_p)))
          {
            source_p += (*source_p == LEXER_NEWLINE_LS_PS_BYTE_1) ? 3 : 1;
            continue;
          }

          if (*source_p == 'x' || *source_p == 'u')
          {
            int hex_part_length = (*source_p == 'x') ? 2 : 4;
            PARSER_ASSERT (source_p + 1 + hex_part_length <= context_p->source_end_p);

            destination_p += util_to_utf8_bytes (destination_p,
                                                 lexer_hex_to_character (context_p,
                                                                         source_p + 1,
                                                                         hex_part_length));
            source_p += hex_part_length + 1;
            continue;
          }

          conv_character = *source_p;
          switch (*source_p)
          {
            case 'b':
            {
              conv_character = 0x08;
              break;
            }
            case 't':
            {
              conv_character = 0x09;
              break;
            }
            case 'n':
            {
              conv_character = 0x0a;
              break;
            }
            case 'v':
            {
              conv_character = 0x0b;
              break;
            }
            case 'f':
            {
              conv_character = 0x0c;
              break;
            }
            case 'r':
            {
              conv_character = 0x0d;
              break;
            }
          }

          if (conv_character != *source_p)
          {
            *destination_p++ = conv_character;
            source_p++;
            continue;
          }
        }

        if (*source_p >= LEXER_UTF8_4BYTE_START)
        {
          /* Processing 4 byte unicode sequence (even if it is
           * after a backslash). Always converted to two 3 byte
           * long sequence. */

          uint32_t character = ((((uint32_t) source_p[0]) & 0x7) << 18);
          character |= ((((uint32_t) source_p[1]) & 0x3f) << 12);
          character |= ((((uint32_t) source_p[2]) & 0x3f) << 6);
          character |= (((uint32_t) source_p[3]) & 0x3f);

          PARSER_ASSERT (character >= 0x10000);
          character -= 0x10000;
          destination_p += util_to_utf8_bytes (destination_p, 0xd800 | (character >> 10));
          destination_p += util_to_utf8_bytes (destination_p, 0xdc00 | (character & 0x3ff));
          source_p += 4;
          continue;
        }

        *destination_p++ = *source_p++;
        while ((*source_p & UTF8_INTERMEDIATE_OCTET_MASK) == UTF8_INTERMEDIATE_OCTET)
        {
          *destination_p++ = *source_p++;
        }
      }

      PARSER_ASSERT (destination_p == destination_start_p + literal_p->length);
    }

    source_p = destination_start_p;
  }

  lexer_process_char_literal (context_p,
                              source_p,
                              literal_p->length,
                              literal_type);

  if (destination_start_p != local_byte_array)
  {
    parser_free_local (destination_start_p);
  }
} /* lexer_construct_literal_object */

#undef LEXER_MAX_LITERAL_LOCAL_BUFFER_SIZE

/**
 * Next token must be an identifier.
 */
void
lexer_expect_identifier (parser_context *context_p, /**< context */
                         uint8_t literal_type) /**< literal type */
{
  skip_spaces (context_p);

  PARSER_ASSERT (literal_type == LEXER_STRING_LITERAL
                 || literal_type == LEXER_VAR_LITERAL);

  context_p->token.line = context_p->line;
  context_p->token.column = context_p->column;

  if (context_p->source_p < context_p->source_end_p
      && (util_is_identifier_start (context_p->source_p) || context_p->source_p[0] == '\\'))
  {
    lexer_parser_identifier (context_p, literal_type != LEXER_STRING_LITERAL);
    lexer_construct_literal_object (context_p,
                                    &context_p->token.char_literal,
                                    literal_type);
  }
  else
  {
    parser_raise_error (context_p, "Identifier expected.");
  }
} /* lexer_expect_identifier */

/**
 * Compares two identifiers.
 *
 * @return non-zero if the input identifiers are the same
 */
int
lexer_same_identifiers (lexer_char_literal *left, /**< left identifier */
                        lexer_char_literal *right) /**< right identifier */
{
  if (left->length != right->length)
  {
    return 0;
  }

  if (!left->has_escape && !right->has_escape)
  {
    return memcmp (left->char_p, right->char_p, left->length) == 0;
  }

  /* TODO implement this. */
  PARSER_ASSERT (0);

  return 0;
} /* lexer_same_identifiers */
