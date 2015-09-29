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

/**
 * While statement.
 */
typedef struct
{
  parser_branch branch;             /**< branch to the end */
  lexer_range range;                /**< condition part */
  uint32_t start_offset;            /**< start byte code offset */
} parser_while_statement;

/**
 * Returns the data consumed by a statement. It can be used
 * to skip undesired frames on the stack during frame search.
 *
 * @return size consumed by the statement.
 */
size_t
parser_statement_length (uint8_t type)
{
  switch (type)
  {
    case LEXER_LEFT_BRACE:
    {
      return 1;
    }

    case LEXER_LABEL:
    {
      return sizeof (lexer_char_literal) + 1;
    }

    case LEXER_KEYW_DO:
    {
      return sizeof (uint32_t) + 1;
    }

    case LEXER_KEYW_WHILE:
    {
      return sizeof (parser_while_statement) + 1;
    }

    default:
    {
      PARSER_ASSERT (0);
      return 0;
    }
  }
}

/**
 * Initialize a range from the current location.
 */
static void PARSER_INLINE
parser_save_range (parser_context *context_p, /**< context */
                   lexer_range *range_p) /**< destination range */
{
  range_p->source_p = context_p->source_p;
  range_p->line = context_p->line;
  range_p->column = context_p->column;
} /* parser_save_range */

/**
 * Set the current location on the stack.
 */
static void PARSER_INLINE
parser_set_range (parser_context *context_p, /**< context */
                  lexer_range *range_p) /**< destination range */
{
  context_p->source_p = range_p->source_p;
  context_p->source_end_p = range_p->source_end_p;
  context_p->line = range_p->line;
  context_p->column = range_p->column;
} /* parser_set_range */

/**
 * Scan for a token on the stack.
 */
static void PARSER_INLINE
parser_scan_until (parser_context *context_p, /**< context */
                   lexer_range *range_p, /**< destination range */
                   lexer_token_type type) /**< token type */
{
  size_t depth = 0;

  parser_save_range (context_p, range_p);

  lexer_next_token (context_p);

  while (context_p->token.type != type || depth > 0)
  {
    if (context_p->token.type == LEXER_EOS)
    {
      parser_raise_error (context_p, "Unexpected end of stream.");
    }

    if (LEXER_IS_LEFT_BRACKET (context_p->token.type))
    {
      depth++;
    }

    if (LEXER_IS_RIGHT_BRACKET (context_p->token.type))
    {
      if (depth == 0)
      {
        parser_raise_error (context_p, "Unexpected closing bracket.");
      }
      depth--;
    }

    range_p->source_end_p = context_p->source_p;
    lexer_next_token (context_p);
  }

  lexer_next_token (context_p);
}

#define PARSER_SAVE_STACK_POSITION() \
  do \
  { \
    context_p->last_statement.current_p = context_p->stack.first_p; \
    context_p->last_statement.current_position = context_p->stack.last_position; \
  } \
  while (0)

/**
 * Parse var statement.
 */
static void
parser_parse_var_statement (parser_context *context_p) /**< context */
{
  PARSER_ASSERT (context_p->token.type == LEXER_KEYW_VAR);

  while (1)
  {
    lexer_expect_identifier (context_p, LEXER_VAR_LITERAL);
    PARSER_ASSERT (context_p->token.type == LEXER_LITERAL
                   && context_p->token.literal_type == LEXER_VAR_LITERAL);

    parser_emit_cbc_literal_from_token (context_p, CBC_PUSH_IDENT);

    lexer_next_token (context_p);

    if (context_p->token.type == LEXER_ASSIGN)
    {
      parser_parse_expression (context_p, PARSE_EXPR_STATEMENT | PARSE_EXPR_NO_COMMA | PARSE_EXPR_HAS_IDENT);
    }
    else
    {
      PARSER_ASSERT (context_p->last_cbc_opcode == CBC_PUSH_IDENT);
      /* We don't need to assign anything to this variable. */
      context_p->last_cbc_opcode = CBC_END;
    }

    if (context_p->token.type != LEXER_COMMA)
    {
      break;
    }
  }
}

/**
 * Parse do-while statement.
 */
static void
parser_parse_do_while_statement_end (parser_context *context_p) /**< context */
{
  uint32_t byte_code_offset;

  PARSER_ASSERT (context_p->stack_top_uint8 == LEXER_KEYW_DO);

  if (context_p->token.type != LEXER_KEYW_WHILE)
  {
    parser_raise_error (context_p, "While expected after do-while loop.");
  }

  lexer_next_token (context_p);
  if (context_p->token.type != LEXER_LEFT_PAREN)
  {
    parser_raise_error (context_p, "Missing '(' after while.");
  }

  parser_parse_expression (context_p, PARSE_EXPR);

  parser_stack_pop_uint8 (context_p);
  parser_stack_peek (context_p, &byte_code_offset, sizeof (uint32_t));
  parser_stack_pop (context_p, sizeof (uint32_t));
  PARSER_SAVE_STACK_POSITION ();

  parser_emit_cbc_backward_branch (context_p, CBC_BRANCH_IF_TRUE_BACKWARD, byte_code_offset);
} /* parser_parse_do_while_statement */

/**
 * Parse while statement (starting part).
 */
static void
parser_parse_while_statement_start (parser_context *context_p) /**< context */
{
  parser_while_statement statement;

  PARSER_ASSERT (context_p->token.type == LEXER_KEYW_WHILE);

  lexer_next_token (context_p);

  if (context_p->token.type != LEXER_LEFT_PAREN)
  {
    parser_raise_error (context_p, "Missing '(' after while.");
  }

  parser_emit_cbc_forward_branch (context_p, CBC_JUMP_FORWARD, &statement.branch);

  PARSER_ASSERT (context_p->last_cbc_opcode == CBC_END);
  statement.start_offset = context_p->byte_code_size;

  /* The conditional part is processed at the end. */
  parser_scan_until (context_p, &statement.range, LEXER_RIGHT_PAREN);

  parser_stack_push (context_p, &statement, sizeof (parser_while_statement));
  parser_stack_push_uint8 (context_p, LEXER_KEYW_WHILE);
  PARSER_SAVE_STACK_POSITION ();
} /* parser_parse_while_statement_start */

/**
 * Parse while statement (ending part).
 */
static void PARSER_NOINLINE
parser_parse_while_statement_end (parser_context *context_p) /**< context */
{
  parser_while_statement statement;
  lexer_token current_token;
  lexer_range range;
  cbc_opcode opcode;

  PARSER_ASSERT (context_p->stack_top_uint8 == LEXER_KEYW_WHILE);

  parser_stack_pop_uint8 (context_p);
  parser_stack_peek (context_p, &statement, sizeof (parser_while_statement));
  parser_stack_pop (context_p, sizeof (parser_while_statement));
  PARSER_SAVE_STACK_POSITION ();

  parser_save_range (context_p, &range);
  range.source_end_p = context_p->source_end_p;
  current_token = context_p->token;

  PARSER_ASSERT (context_p->last_cbc_opcode == CBC_END);
  parser_set_branch_to_current_position (context_p, &statement.branch);

  parser_set_range (context_p, &statement.range);
  lexer_next_token (context_p);

  parser_parse_expression (context_p, PARSE_EXPR);

  if (context_p->token.type != LEXER_EOS)
  {
    parser_raise_error (context_p, "Invalid expression.");
  }

  opcode = CBC_BRANCH_IF_TRUE_BACKWARD;
  if (context_p->last_cbc_opcode == CBC_LOGICAL_NOT)
  {
    context_p->last_cbc_opcode = CBC_END;
    opcode = CBC_BRANCH_IF_FALSE_BACKWARD;
  }

  parser_emit_cbc_backward_branch (context_p, opcode, statement.start_offset);

  parser_set_range (context_p, &range);
  context_p->token = current_token;
} /* parser_parse_while_statement_end */

/**
 * Parse label statement.
 */
static void
parser_parse_label (parser_context *context_p, /**< context */
                    lexer_char_literal *ident_literal) /**< saved literal */
{
  parser_stack_iterator iterator;
  lexer_char_literal label;

  parser_stack_iterator_init (context_p, &iterator);

  while (1)
  {
    uint8_t type = parser_stack_iterator_read_uint8 (&iterator);
    if (type == LEXER_STATEMENT_START)
    {
      break;
    }

    if (type == LEXER_LABEL)
    {
      parser_stack_iterator_skip (&iterator, 1);
      parser_stack_iterator_read (&iterator, &label, sizeof (lexer_char_literal));
      parser_stack_iterator_skip (&iterator, sizeof (lexer_char_literal));

      if (lexer_same_identifiers (ident_literal, &label))
      {
        parser_raise_error (context_p, "Duplicated label.");
      }
    }
    else
    {
      parser_stack_iterator_skip (&iterator, parser_statement_length (type));
    }
  }

printf ("LABEL: ");
util_print_string (ident_literal->char_p, ident_literal->length);
printf ("\n");

  parser_stack_push (context_p, &context_p->token.char_literal, sizeof (lexer_char_literal));
  parser_stack_push_uint8 (context_p, LEXER_LABEL);
  PARSER_SAVE_STACK_POSITION ();
}

/**
 * Parse statements.
 */
static void
parser_parse_statements (parser_context *context_p) /**< context */
{
  enum
  {
    TERMINATOR_REQUIRED,
    TERMINATOR_NOT_REQUIRED,
  } terminator;

  /* Statement parsing cannot be nested. */
  PARSER_ASSERT (context_p->last_statement.current_p == NULL);
  parser_stack_push_uint8 (context_p, LEXER_STATEMENT_START);
  PARSER_SAVE_STACK_POSITION ();

  while (context_p->token.type != LEXER_EOS
         || context_p->stack_top_uint8 != LEXER_STATEMENT_START)
  {
    PARSER_ASSERT (context_p->stack_depth == 0);

    switch (context_p->token.type)
    {
      case LEXER_SEMICOLON:
      case LEXER_RIGHT_BRACE:
      {
        break;
      }

      case LEXER_LEFT_BRACE:
      {
        parser_stack_push_uint8 (context_p, LEXER_LEFT_BRACE);
        PARSER_SAVE_STACK_POSITION ();
        lexer_next_token (context_p);
        continue;
        /* FALLTHRU */
      }

      case LEXER_KEYW_VAR:
      {
        parser_parse_var_statement (context_p);
        break;
      }

      case LEXER_KEYW_DO:
      {
        PARSER_ASSERT (context_p->last_cbc_opcode == CBC_END);
        parser_stack_push (context_p, &context_p->byte_code_size, sizeof (uint32_t));
        parser_stack_push_uint8 (context_p, LEXER_KEYW_DO);
        PARSER_SAVE_STACK_POSITION ();
        lexer_next_token (context_p);
        continue;
        /* FALLTHRU */
      }

      case LEXER_KEYW_WHILE:
      {
        parser_parse_while_statement_start (context_p);
        continue;
        /* FALLTHRU */
      }

      case LEXER_LITERAL:
      {
        if (context_p->token.literal_type == LEXER_IDENT_LITERAL)
        {
          lexer_char_literal char_literal = context_p->token.char_literal;

          lexer_next_token (context_p);

          if (context_p->token.type == LEXER_COLON)
          {
            parser_parse_label (context_p, &char_literal);
            lexer_next_token (context_p);
            continue;
          }

          lexer_construct_literal_object (context_p, &char_literal, LEXER_IDENT_LITERAL);
          parser_emit_cbc_literal_from_token (context_p, CBC_PUSH_IDENT);
          parser_parse_expression (context_p, PARSE_EXPR_STATEMENT | PARSE_EXPR_HAS_IDENT);
          break;
        }
        /* FALLTHRU */
      }

      default:
      {
        parser_parse_expression (context_p, PARSE_EXPR_STATEMENT);
        break;
      }
    }

    parser_flush_cbc (context_p);

    terminator = TERMINATOR_REQUIRED;
    while (1)
    {
      if (terminator == TERMINATOR_REQUIRED)
      {
        if (context_p->token.type == LEXER_RIGHT_BRACE)
        {
          if (context_p->stack_top_uint8 == LEXER_LEFT_BRACE)
          {
            parser_stack_pop_uint8 (context_p);
            PARSER_SAVE_STACK_POSITION ();
            lexer_next_token (context_p);
          }
          else
          {
            parser_raise_error (context_p, "Misplaced '}' token.");
          }
        }
        else if (context_p->token.type == LEXER_SEMICOLON)
        {
          lexer_next_token (context_p);
        }
        else if (context_p->token.type != LEXER_EOS
                 && !context_p->token.was_newline)
        {
          parser_raise_error (context_p, "Missing ';' token.");
        }
      }

      terminator = TERMINATOR_REQUIRED;

      switch (context_p->stack_top_uint8)
      {
        case LEXER_LABEL:
        {
          parser_stack_pop (context_p, sizeof (lexer_char_literal) + 1);
          PARSER_SAVE_STACK_POSITION ();
          terminator = TERMINATOR_NOT_REQUIRED;
          continue;
          /* FALLTHRU */
        }

        case LEXER_KEYW_DO:
        {
          parser_parse_do_while_statement_end (context_p);
          continue;
          /* FALLTHRU */
        }

        case LEXER_KEYW_WHILE:
        {
          parser_parse_while_statement_end (context_p);
          terminator = TERMINATOR_NOT_REQUIRED;
          continue;
          /* FALLTHRU */
        }

        default:
        {
          break;
        }
      }
      break;
    }
  }

  parser_stack_pop_uint8 (context_p);
  context_p->last_statement.current_p = NULL;
}

#undef PARSER_SAVE_STACK_POSITION

/**
 * Free identifiers and literals.
 */
static void
parser_free_lists (parser_context *context_p) /**< context */
{
  parser_list_iterator literal_iterator;
  lexer_literal *literal_p;

  parser_list_iterator_init (&context_p->literal_pool, &literal_iterator);
  while ((literal_p = (lexer_literal *) parser_list_iterator_next (&literal_iterator)) != NULL)
  {
    util_free_literal (literal_p);
  }

  parser_list_free (&context_p->literal_pool);
} /* parser_free_identifiers */

/**
 * Free jumps stored on the stack.
 */
static void PARSER_NOINLINE
parser_free_jumps (parser_context *context_p) /**< context */
{
  while (1)
  {
    uint8_t type = parser_stack_iterator_read_uint8 (&context_p->last_statement);
    if (type == LEXER_STATEMENT_START)
    {
      return;
    }

    parser_stack_iterator_skip (&context_p->last_statement, parser_statement_length (type));
  }
} /* parser_free_jumps */

/**
 * Parse EcmaScript source code
 */
void
parser_parse_script (const uint8_t *source_p, size_t size)
{
  parser_context context;

  context.error_str_p = NULL;

  context.is_strict = 0;
  context.stack_depth = 0;
  context.stack_max_depth = 0;
  context.last_statement.current_p = NULL;
#ifdef PARSER_DEBUG
  context.is_show_opcodes = 1;
#endif

  context.source_p = source_p;
  context.source_end_p = source_p + size;
  context.line = 1;
  context.column = 1;

  context.last_cbc_opcode = CBC_END;

  context.var_count = 0;
  context.ident_count = 0;
  context.other_count = 0;

  parser_cbc_stream_init (&context.byte_code);
  context.byte_code_size = 0;
  parser_list_init (&context.literal_pool, sizeof (lexer_literal), 15);
  parser_stack_init (&context);

  PARSER_TRY (context.try_buffer)
  {
    /* Pushing a dummy value ensures the stack is never empty.
     * This simplifies the stack management routines. */
    parser_stack_push_uint8 (&context, CBC_MAXIMUM_BYTE_VALUE);
    /* The next token must always be present to make decisions
     * in the parser. Therefore when a token is consumed, the
     * lexer_next_token() must be immediately called. */
    lexer_next_token (&context);

    parser_parse_statements (&context);

    /* When the parsing is successful, only the
     * dummy value can be remained on the stack. */
    PARSER_ASSERT (context.stack_top_uint8 == CBC_MAXIMUM_BYTE_VALUE
                   && context.stack.last_position == 1
                   && context.stack.first_p != NULL
                   && context.stack.first_p->next_p == NULL
                   && context.stack.last_p == NULL);
    PARSER_ASSERT (context.last_statement.current_p == NULL);

    parser_flush_cbc (&context);
    parser_post_processing (&context);
  }
  PARSER_CATCH
  {
    if (context.last_statement.current_p != NULL)
    {
      parser_free_jumps (&context);
    }

    printf ("Parse error '%s' at line: %d col: %d\n",
            context.error_str_p,
            (int) context.token.line,
            (int) context.token.column);
  }
  PARSER_TRY_END

  parser_cbc_stream_free (&context.byte_code);
  parser_free_lists (&context);
  parser_stack_free (&context);
} /* parser_parse_script */
