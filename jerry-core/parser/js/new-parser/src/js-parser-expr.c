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

static const uint8_t parser_binary_precedence_table[36] =
{
  3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
  4, 5, 6, 7, 8, 9, 10, 10, 10, 10,
  11, 11, 11, 11, 11, 11, 12, 12, 12,
  13, 13, 14, 14, 14
};

/**
 * Generate byte code for operators with lvalue.
 */
static void PARSER_INLINE
parser_push_result (parser_context *context_p) /**< context */
{
  if (CBC_NO_RESULT_OPERATION (context_p->last_cbc_opcode))
  {
    PARSER_ASSERT (CBC_SAME_ARGS (context_p->last_cbc_opcode, context_p->last_cbc_opcode + 1));
    context_p->last_cbc_opcode++;
    parser_flush_cbc (context_p);
  }
} /* parser_push_result */

/**
 * Generate byte code for operators with lvalue.
 */
static void
parser_emit_lvalue_opcode (parser_context *context_p, /**< context */
                           cbc_opcode opcode) /**< opcode */
{
  if (context_p->last_cbc_opcode == CBC_PUSH_IDENT)
  {
    PARSER_ASSERT (CBC_SAME_ARGS (CBC_PUSH_IDENT, opcode + CBC_LVALUE_WITH_IDENT));
    context_p->last_cbc_opcode = opcode + CBC_LVALUE_WITH_IDENT;
  }
  else if (context_p->last_cbc_opcode == CBC_PROP_GET)
  {
    PARSER_ASSERT (CBC_SAME_ARGS (CBC_PROP_GET, opcode));
    context_p->last_cbc_opcode = opcode;
  }
  else if (context_p->last_cbc_opcode == CBC_PROP_STRING_GET)
  {
    PARSER_ASSERT (CBC_SAME_ARGS (CBC_PROP_STRING_GET, opcode + CBC_LVALUE_WITH_PROP_STRING));
    context_p->last_cbc_opcode = opcode + CBC_LVALUE_WITH_PROP_STRING;
  }
  else
  {
    /* A runtime error will happen. */
    parser_emit_cbc (context_p, CBC_PUSH_UNDEFINED_BASE);
    parser_emit_cbc (context_p, opcode);
  }
} /* parser_emit_lvalue_opcode */

/**
 * Parse and record unary operators, and parse the primary literal.
 */
static void
parser_parse_unary_expression (parser_context *context_p, /**< context */
                               size_t *grouping_level_p) /**< grouping level */
{
  int new_was_seen = 0;

  /* Collect unary operators. */
  while (1)
  {
    /* Convert plus and minus binary operators to unary operators. */
    if (context_p->token.type == LEXER_BINARY_ADD)
    {
      context_p->token.type = LEXER_UNARY_PLUS;
    }
    else if (context_p->token.type == LEXER_BINARY_SUBTRACT)
    {
      context_p->token.type = LEXER_UNARY_NEGATE;
    }

    /* Bracketed expressions are primary expressions. At this
     * point their left paren is pushed onto the stack and
     * they are processed when their closing paren is reached. */
    if (context_p->token.type == LEXER_LEFT_PAREN)
    {
      (*grouping_level_p)++;
      new_was_seen = 0;
    }
    else if (context_p->token.type == LEXER_KEYW_NEW)
    {
      /* After 'new' unary operators are not allowed. */
      new_was_seen = 1;
    }
    else if (new_was_seen || !LEXER_IS_UNARY_OP_TOKEN (context_p->token.type))
    {
      break;
    }

    parser_stack_push_uint8 (context_p, context_p->token.type);
    lexer_next_token (context_p);
  }

  /* Parse primary expression. */
  switch (context_p->token.type)
  {
    case LEXER_LITERAL:
    {
      cbc_opcode opcode = CBC_PUSH_LITERAL;

      if (context_p->token.literal_type == LEXER_IDENT_LITERAL
          || context_p->token.literal_type == LEXER_STRING_LITERAL)
      {
        lexer_construct_literal_object (context_p,
                                        &context_p->token.char_literal,
                                        context_p->token.literal_type);
      }

      if (context_p->token.literal_type == LEXER_IDENT_LITERAL)
      {
        opcode = CBC_PUSH_IDENT;
      }

      parser_emit_cbc_literal_from_token (context_p, opcode);
      break;
    }
    case LEXER_KEYW_THIS:
    {
      parser_emit_cbc (context_p, CBC_PUSH_THIS);
      break;
    }
    case LEXER_LIT_TRUE:
    {
      parser_emit_cbc (context_p, CBC_PUSH_TRUE);
      break;
    }
    case LEXER_LIT_FALSE:
    {
      parser_emit_cbc (context_p, CBC_PUSH_FALSE);
      break;
    }
    case LEXER_LIT_NULL:
    {
      parser_emit_cbc (context_p, CBC_PUSH_NULL);
      break;
    }
    default:
    {
      parser_raise_error (context_p, "Primary expression expected.");
      break;
    }
  }
  lexer_next_token (context_p);
} /* parser_parse_unary_expression */

/**
 * Parse the postfix part of unary operators, and
 * generate byte code for the whole expression.
 */
static void
parser_process_unary_expression (parser_context *context_p) /**< context */
{
  /* Parse postfix part of a primary expression. */
  while (1)
  {
    /* Since break would only break the switch, we use
     * continue to continue this loop. Without continue,
     * the code abandons the loop. */
    switch (context_p->token.type)
    {
      case LEXER_DOT:
      {
        parser_push_result (context_p);

        lexer_expect_identifier (context_p, LEXER_STRING_LITERAL);
        PARSER_ASSERT (context_p->token.type == LEXER_LITERAL
                       && context_p->token.literal_type == LEXER_STRING_LITERAL);
        parser_emit_cbc_literal_from_token (context_p, CBC_PROP_STRING_GET);
        lexer_next_token (context_p);
        continue;
        /* FALLTHRU */
      }

      case LEXER_LEFT_SQUARE:
      {
        parser_push_result (context_p);

        lexer_next_token (context_p);
        parser_parse_expression (context_p, PARSE_EXPR);
        if (context_p->token.type != LEXER_RIGHT_SQUARE)
        {
          parser_raise_error (context_p, "Missing ']' token.");
        }
        lexer_next_token (context_p);

        if (context_p->last_cbc_opcode == CBC_PUSH_LITERAL
            && context_p->last_cbc_arg.literal_type == LEXER_STRING_LITERAL)
        {
          context_p->last_cbc_opcode = CBC_PROP_STRING_GET;
        }
        else
        {
          parser_emit_cbc (context_p, CBC_PROP_GET);
        }
        continue;
        /* FALLTHRU */
      }

      case LEXER_LEFT_PAREN:
      {
        size_t call_arguments = 0;
        cbc_argument argument = context_p->last_cbc_arg;
        uint8_t opcode;

        parser_push_result (context_p);

        if (context_p->stack_top_uint8 == LEXER_KEYW_NEW)
        {
          parser_stack_pop_uint8 (context_p);
          if (context_p->last_cbc_opcode == CBC_PUSH_IDENT)
          {
            context_p->last_cbc_opcode = CBC_END;
            opcode = CBC_NEW_IDENT;
          }
          else
          {
            opcode = CBC_NEW;
          }
        }
        else
        {
          if (context_p->last_cbc_opcode == CBC_PUSH_IDENT)
          {
            context_p->last_cbc_opcode = CBC_END;
            opcode = CBC_CALL_IDENT;
          }
          else if (context_p->last_cbc_opcode == CBC_PROP_GET)
          {
            context_p->last_cbc_opcode = CBC_END;
            opcode = CBC_CALL_PROP;
          }
          else if (context_p->last_cbc_opcode == CBC_PROP_STRING_GET)
          {
            context_p->last_cbc_opcode = CBC_END;
            opcode = CBC_CALL_PROP_STRING;
          }
          else
          {
            opcode = CBC_CALL;
          }
        }

        lexer_next_token (context_p);

        if (context_p->token.type != LEXER_RIGHT_PAREN)
        {
          while (1)
          {
            if (++call_arguments > CBC_MAXIMUM_BYTE_VALUE)
            {
              parser_raise_error (context_p, "Too many arguments for a function call.");
            }

            parser_parse_expression (context_p, PARSE_EXPR_NO_COMMA);

            if (context_p->token.type != LEXER_COMMA)
            {
              break;
            }
            lexer_next_token (context_p);
          }

          if (context_p->token.type != LEXER_RIGHT_PAREN)
          {
            parser_raise_error (context_p, "Missing ')' token.");
          }
        }

        lexer_next_token (context_p);
        parser_flush_cbc (context_p);

        /* Pushing the next instruction manually. */
        argument.byte_argument = call_arguments;
        context_p->last_cbc_arg = argument;
        context_p->last_cbc_opcode = opcode;
        continue;
        /* FALLTHRU */
      }

      default:
      {
        if (context_p->stack_top_uint8 == LEXER_KEYW_NEW)
        {
          /* Push result is unnecessary since new has higher precedence than call. */
          if (context_p->last_cbc_opcode == CBC_PUSH_IDENT)
          {
            context_p->last_cbc_opcode = CBC_NEW_IDENT;
            context_p->last_cbc_arg.byte_argument = 0;
          }
          else
          {
            parser_emit_cbc_call (context_p, CBC_NEW, 0);
          }
          parser_stack_pop_uint8 (context_p);
          continue;
        }
        if (!context_p->token.was_newline
            && (context_p->token.type == LEXER_INCREASE || context_p->token.type == LEXER_DECREASE))
        {
          cbc_opcode opcode = (context_p->token.type == LEXER_INCREASE) ? CBC_POST_INCR : CBC_POST_DECR;
          parser_push_result (context_p);
          parser_emit_lvalue_opcode (context_p, opcode);
          lexer_next_token (context_p);
        }
        break;
      }
    }
    break;
  }

  /* Generate byte code for the unary operators. */
  while (1)
  {
    uint8_t token = context_p->stack_top_uint8;
    if (!LEXER_IS_UNARY_OP_TOKEN (token))
    {
      break;
    }

    parser_push_result (context_p);
    parser_stack_pop_uint8 (context_p);

    if (LEXER_IS_UNARY_LVALUE_OP_TOKEN (token))
    {
      token = CBC_UNARY_LVALUE_OP_TOKEN_TO_OPCODE (token);
      parser_emit_lvalue_opcode (context_p, token);
    }
    else
    {
      token = CBC_UNARY_OP_TOKEN_TO_OPCODE (token);
      if (context_p->last_cbc_opcode == CBC_PUSH_IDENT
          || context_p->last_cbc_opcode == CBC_PUSH_LITERAL)
      {
        PARSER_ASSERT (CBC_SAME_ARGS (context_p->last_cbc_opcode, token + 1));
        context_p->last_cbc_opcode = token + 1;
      }
      else
      {
        parser_emit_cbc (context_p, token);
      }
    }
  }
} /* parser_process_unary_expression */

/**
 * Append a binary token.
 */
static void
parser_append_binary_token (parser_context *context_p) /**< context */
{
  PARSER_ASSERT (LEXER_IS_BINARY_OP_TOKEN (context_p->token.type));

  parser_push_result (context_p);

  /* Unlike unary tokens, the whole byte code is saved for binary
   * operators, since they have multiple forms depending on the
   * previos instruction. */

  if (LEXER_IS_BINARY_LVALUE_TOKEN (context_p->token.type))
  {
    cbc_opcode opcode = CBC_BINARY_LVALUE_OP_TOKEN_TO_OPCODE (context_p->token.type);

    if (context_p->last_cbc_opcode == CBC_PUSH_IDENT)
    {
      PARSER_ASSERT (CBC_SAME_ARGS (CBC_PUSH_IDENT, opcode + CBC_LVALUE_WITH_IDENT));
      parser_stack_push_uint16 (context_p, context_p->last_cbc_arg.literal_index);
      parser_stack_push_uint8 (context_p, opcode + CBC_LVALUE_WITH_IDENT);
      context_p->last_cbc_opcode = CBC_END;
    }
    else if (context_p->last_cbc_opcode == CBC_PROP_GET)
    {
      PARSER_ASSERT (CBC_SAME_ARGS (CBC_PROP_GET, opcode));
      parser_stack_push_uint8 (context_p, opcode);
      context_p->last_cbc_opcode = CBC_END;
    }
    else if (context_p->last_cbc_opcode == CBC_PROP_STRING_GET)
    {
      PARSER_ASSERT (CBC_SAME_ARGS (CBC_PROP_STRING_GET, opcode + CBC_LVALUE_WITH_PROP_STRING));
      parser_stack_push_uint16 (context_p, context_p->last_cbc_arg.literal_index);
      parser_stack_push_uint8 (context_p, opcode + CBC_LVALUE_WITH_PROP_STRING);
      context_p->last_cbc_opcode = CBC_END;
    }
    else
    {
      /* A runtime error will happen. */
      parser_emit_cbc (context_p, CBC_PUSH_UNDEFINED_BASE);
      parser_stack_push_uint8 (context_p, opcode);
    }
  }
  else
  {
    cbc_opcode opcode = CBC_BINARY_OP_TOKEN_TO_OPCODE (context_p->token.type);

    if (context_p->last_cbc_opcode == CBC_PUSH_IDENT
        || context_p->last_cbc_opcode == CBC_PUSH_LITERAL)
    {
      PARSER_ASSERT (CBC_SAME_ARGS (context_p->last_cbc_opcode, opcode + 1));
      parser_stack_push_uint16 (context_p, context_p->last_cbc_arg.literal_index);
      parser_stack_push_uint8 (context_p, opcode + 1);
      context_p->last_cbc_opcode = CBC_END;
    }
    else
    {
      parser_stack_push_uint8 (context_p, opcode);
    }
  }
  parser_stack_push_uint8 (context_p, context_p->token.type);
}

/**
 * Emit opcode for binary computations.
 */
static void
parser_process_binary_opcodes (parser_context *context_p, /**< context */
                               uint8_t min_prec_treshold) /**< minimal precedence of tokens */
{
  while (1)
  {
    uint8_t token = context_p->stack_top_uint8;
    cbc_opcode opcode;

    /* For left-to-right operators (all binary operators except assignment),
     * the byte code is flushed if the precedence of the next operator is
     * less or equal than the current operator. For assignment operators,
     * we add 1 to the min precendence to force right-to-left computation
     * order. */

    if (!LEXER_IS_BINARY_OP_TOKEN (token)
        || parser_binary_precedence_table[token - LEXER_FIRST_BINARY_OP] < min_prec_treshold)
    {
      return;
    }

    parser_push_result (context_p);
    parser_stack_pop_uint8 (context_p);
    opcode = context_p->stack_top_uint8;
    parser_stack_pop_uint8 (context_p);

    if (!LEXER_IS_BINARY_LVALUE_TOKEN (token)
        && !(cbc_flags[opcode] & CBC_HAS_LITERAL_ARG))
    {
      if (context_p->last_cbc_opcode == CBC_PUSH_IDENT
          || context_p->last_cbc_opcode == CBC_PUSH_LITERAL)
      {
        PARSER_ASSERT (CBC_SAME_ARGS (context_p->last_cbc_opcode, opcode + 2));
        context_p->last_cbc_opcode = opcode + 2;
        continue;
      }
    }

    if (cbc_flags[opcode] & CBC_HAS_LITERAL_ARG)
    {
      uint16_t index = parser_stack_pop_uint16 (context_p);
      parser_emit_cbc_literal (context_p, opcode, index);
    }
    else
    {
      parser_emit_cbc (context_p, opcode);
    }
  }
}

/**
 * Parse expression.
 */
void
parser_parse_expression (parser_context *context_p, /**< context */
                         int options) /**< option flags */
{
  size_t grouping_level = 0;

  parser_stack_push_uint8 (context_p, LEXER_EXPRESSION_START);

  while (1)
  {
    if (options & PARSE_EXPR_HAS_IDENT)
    {
      PARSER_ASSERT (context_p->last_cbc_opcode == CBC_PUSH_IDENT);
      /* True only for the first expression. */
      options &= ~PARSE_EXPR_HAS_IDENT;
    }
    else
    {
      parser_parse_unary_expression (context_p, &grouping_level);
    }

    while (1)
    {
      parser_process_unary_expression (context_p);

      /* The engine flush binary opcodes above this precedence. */
      uint8_t min_prec_treshold = CBC_MAXIMUM_BYTE_VALUE;

      if (LEXER_IS_BINARY_OP_TOKEN (context_p->token.type))
      {
        min_prec_treshold = parser_binary_precedence_table[context_p->token.type - LEXER_FIRST_BINARY_OP];
        if (LEXER_IS_BINARY_LVALUE_TOKEN (context_p->token.type))
        {
          /* Right-to-left evaluation order. */
          min_prec_treshold++;
        }
      }
      else
      {
        min_prec_treshold = 0;
      }

      parser_process_binary_opcodes (context_p, min_prec_treshold);

      if (context_p->token.type == LEXER_RIGHT_PAREN
          && context_p->stack_top_uint8 == LEXER_LEFT_PAREN)
      {
        PARSER_ASSERT (grouping_level > 0);
        grouping_level --;
        parser_stack_pop_uint8 (context_p);
        lexer_next_token (context_p);
        continue;
      }
      else if (context_p->token.type == LEXER_QUESTION_MARK)
      {
        cbc_opcode opcode = CBC_BRANCH_IF_FALSE_FORWARD;
        parser_branch cond_branch;
        parser_branch uncond_branch;

        if (context_p->last_cbc_opcode == CBC_LOGICAL_NOT)
        {
          context_p->last_cbc_opcode = CBC_END;
          opcode = CBC_BRANCH_IF_TRUE_FORWARD;
        }

        parser_emit_cbc_forward_branch (context_p, opcode, &cond_branch);

        lexer_next_token (context_p);
        parser_parse_expression (context_p, PARSE_EXPR_NO_COMMA);
        parser_emit_cbc_forward_branch (context_p, CBC_JUMP_FORWARD, &uncond_branch);
        parser_set_branch_to_current_position (context_p, &cond_branch);

        /* Although byte code is constructed for two branches,
         * only one of them will be executed. To reflect this
         * the stack is manually adjusted. */
        PARSER_ASSERT (context_p->stack_depth > 0);
        context_p->stack_depth--;

        if (context_p->token.type != LEXER_COLON)
        {
          parser_raise_error (context_p, "Colon expected for ?: operator.");
        }

        lexer_next_token (context_p);

        parser_parse_expression (context_p, PARSE_EXPR_NO_COMMA);
        parser_set_branch_to_current_position (context_p, &uncond_branch);

        /* Last opcode rewrite is not allowed because
         * the result may come from the first branch. */
        parser_flush_cbc (context_p);
        continue;
      }
      break;
    }

    if (context_p->token.type == LEXER_COMMA)
    {
      if (!(options & PARSE_EXPR_NO_COMMA) || grouping_level > 0)
      {
        if (!CBC_NO_RESULT_OPERATION (context_p->last_cbc_opcode))
        {
          parser_emit_cbc (context_p, CBC_POP);
        }
        lexer_next_token (context_p);
        continue;
      }
    }
    else if (LEXER_IS_BINARY_OP_TOKEN (context_p->token.type))
    {
      parser_append_binary_token (context_p);
      lexer_next_token (context_p);
      continue;
    }
    break;
  }

  if (grouping_level != 0)
  {
    parser_raise_error (context_p, "Missing ')' token.");
  }

  PARSER_ASSERT (context_p->stack_top_uint8 == LEXER_EXPRESSION_START);
  parser_stack_pop_uint8 (context_p);

  if (options & PARSE_EXPR_STATEMENT)
  {
    if (!CBC_NO_RESULT_OPERATION (context_p->last_cbc_opcode))
    {
      parser_emit_cbc (context_p, CBC_POP);
    }
  }
  else
  {
    parser_push_result (context_p);
  }
} /* parser_parse_expression */
