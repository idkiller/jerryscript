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

/**********************************************************************/
/* Error management                                                   */
/**********************************************************************/

/**
 * Raise a parse error
 */
void
parser_raise_error (parser_context *context_p, /**< context */
                    char *error_str_p) /**< error message */
{
  context_p->error_str_p = error_str_p;
  PARSER_THROW (context_p->try_buffer);
  /* Should never been reached. */
  PARSER_ASSERT (0);
} /* parser_raise_error */

/**********************************************************************/
/* Emitting byte codes                                                */
/**********************************************************************/

/**
 * Append two bytes to the cbc stream.
 */
static void
parser_emit_two_bytes (parser_context *context_p, /**< context */
                       uint8_t first_byte, /**< first byte */
                       uint8_t second_byte) /**< second byte */
{
  size_t last_position = context_p->byte_code.last_position;

  if (last_position + 2 <= PARSER_CBC_STREAM_PAGE_SIZE)
  {
    parser_mem_page *page_p = context_p->byte_code.last_p;

    page_p->bytes[last_position] = first_byte;
    page_p->bytes[last_position + 1] = second_byte;
    context_p->byte_code.last_position = last_position + 2;
  }
  else if (last_position >= PARSER_CBC_STREAM_PAGE_SIZE)
  {
    parser_mem_page *page_p;

    parser_cbc_stream_alloc_page (context_p, &context_p->byte_code);
    page_p = context_p->byte_code.last_p;
    page_p->bytes[0] = first_byte;
    page_p->bytes[1] = second_byte;
    context_p->byte_code.last_position = 2;
  }
  else
  {
    context_p->byte_code.last_p->bytes[PARSER_CBC_STREAM_PAGE_SIZE - 1] = first_byte;
    parser_cbc_stream_alloc_page (context_p, &context_p->byte_code);
    context_p->byte_code.last_p->bytes[0] = second_byte;
    context_p->byte_code.last_position = 1;
  }
}

#define PARSER_APPEND_TO_BYTE_CODE(context_p, byte) \
  if ((context_p)->byte_code.last_position >= PARSER_CBC_STREAM_PAGE_SIZE) \
  { \
    parser_cbc_stream_alloc_page ((context_p), &(context_p)->byte_code); \
  } \
  (context_p)->byte_code.last_p->bytes[(context_p)->byte_code.last_position++] = (uint8_t) (byte)

/**
 * Append the current byte code to the stream
 */
void
parser_flush_cbc (parser_context *context_p) /**< context */
{
  if (context_p->last_cbc_opcode != CBC_END)
  {
    uint8_t opcode = context_p->last_cbc_opcode;
    uint8_t flags = cbc_flags[opcode];

    PARSER_APPEND_TO_BYTE_CODE (context_p, opcode);
    context_p->byte_code_size++;

    PARSER_ASSERT ((flags >> CBC_STACK_ADJUST_SHIFT) >= CBC_STACK_ADJUST_BASE
                   || (CBC_STACK_ADJUST_BASE - (flags >> CBC_STACK_ADJUST_SHIFT)) <= context_p->stack_depth);
    context_p->stack_depth += CBC_STACK_ADJUST_VALUE (flags);

    if (flags & CBC_HAS_BYTE_ARG)
    {
      uint8_t byte_argument = context_p->last_cbc_arg.byte_argument;

      if (CBC_IS_CALL_OPCODE (opcode))
      {
        PARSER_ASSERT (context_p->stack_depth >= byte_argument);
        context_p->stack_depth -= byte_argument;
      }

      PARSER_APPEND_TO_BYTE_CODE (context_p, byte_argument);
      context_p->byte_code_size++;
    }

    if (flags & CBC_HAS_LITERAL_ARG)
    {
      uint16_t literal_index = context_p->last_cbc_arg.literal_index;

#if PARSER_MAXIMUM_NUMBER_OF_LITERALS <= CBC_MAXIMUM_BYTE_VALUE
      PARSER_APPEND_TO_BYTE_CODE (context_p, literal_index);
      context_p->byte_code_size++;
#else
      parser_emit_two_bytes (context_p, literal_index & 0xff, literal_index >> 8);
      context_p->byte_code_size += 2;
#endif /* PARSER_MAXIMUM_NUMBER_OF_LITERALS <= CBC_MAXIMUM_BYTE_VALUE */
    }

#ifdef PARSER_DEBUG
    if (context_p->is_show_opcodes)
    {
      printf (" [%3d] %s", (int) context_p->stack_depth, cbc_names[opcode]);

      if (flags & CBC_HAS_LITERAL_ARG)
      {
        uint16_t literal_index = context_p->last_cbc_arg.literal_index;
        lexer_literal *literal_p = parser_list_get (&context_p->literal_pool, literal_index);
        printf (" ");
        util_print_literal (literal_p);
        printf ("-id:%d", literal_index);
      }

      if (flags & CBC_HAS_BYTE_ARG)
      {
        printf (" byte_arg:%d", (int) context_p->last_cbc_arg.byte_argument);
      }

      printf ("\n");
    }
#endif /* PARSER_DEBUG */

    if (context_p->stack_depth > context_p->stack_max_depth)
    {
      context_p->stack_max_depth = context_p->stack_depth;
    }

    context_p->last_cbc_opcode = CBC_END;
  }
} /* parser_flush_cbc */

/**
 * Append a byte code
 */
void
parser_emit_cbc (parser_context *context_p, /**< context */
                 cbc_opcode opcode) /**< opcode */
{
  PARSER_ASSERT ((cbc_flags[opcode] & CBC_ARG_TYPES) == 0);

  if (context_p->last_cbc_opcode != CBC_END)
  {
    parser_flush_cbc (context_p);
  }

  context_p->last_cbc_opcode = opcode;
} /* parser_emit_byte_code */

/**
 * Append a byte code with a literal argument
 */
void
parser_emit_cbc_literal_from_token (parser_context *context_p, /**< context */
                                    cbc_opcode opcode) /**< opcode */
{
  PARSER_ASSERT ((cbc_flags[opcode] & CBC_ARG_TYPES) == CBC_HAS_LITERAL_ARG);

  if (context_p->last_cbc_opcode != CBC_END)
  {
    parser_flush_cbc (context_p);
  }

  context_p->last_cbc_opcode = opcode;
  context_p->last_cbc_arg.literal_index = context_p->token.literal_index;
  context_p->last_cbc_arg.literal_type = context_p->token.literal_type;
} /* parser_emit_cbc_literal_from_token */

/**
 * Append a byte code with a literal argument
 */
void
parser_emit_cbc_literal (parser_context *context_p, /**< context */
                         cbc_opcode opcode, /**< opcode */
                         uint16_t literal_index) /**< literal index */
{
  PARSER_ASSERT ((cbc_flags[opcode] & CBC_ARG_TYPES) == CBC_HAS_LITERAL_ARG);

  if (context_p->last_cbc_opcode != CBC_END)
  {
    parser_flush_cbc (context_p);
  }

  context_p->last_cbc_opcode = opcode;
  context_p->last_cbc_arg.literal_index = literal_index;
  context_p->last_cbc_arg.literal_type = LEXER_UNKNOWN_LITERAL;
} /* parser_emit_cbc_literal */

/**
 * Append a byte code with a call argument
 */
void
parser_emit_cbc_call (parser_context *context_p, /**< context */
                      cbc_opcode opcode, /**< opcode */
                      size_t call_arguments) /**< number of arguments */
{
  PARSER_ASSERT ((cbc_flags[opcode] & CBC_ARG_TYPES) == CBC_HAS_BYTE_ARG);
  PARSER_ASSERT (call_arguments <= CBC_MAXIMUM_BYTE_VALUE);

  if (context_p->last_cbc_opcode != CBC_END)
  {
    parser_flush_cbc (context_p);
  }

  context_p->last_cbc_opcode = opcode;
  context_p->last_cbc_arg.byte_argument = (uint8_t) call_arguments;
} /* parser_emit_cbc_call */

/**
 * Append a byte code with a branch argument
 */
void
parser_emit_cbc_forward_branch (parser_context *context_p, /**< context */
                                cbc_opcode opcode, /**< opcode */
                                parser_branch *branch_p) /**< branch result */
{
  uint8_t flags = cbc_flags[opcode];

  PARSER_ASSERT (flags & CBC_HAS_BRANCH_ARG);
  PARSER_ASSERT (CBC_BRANCH_IS_FORWARD (opcode));
  PARSER_ASSERT (CBC_BRANCH_OFFSET_LENGTH (opcode) == 1);

  if (context_p->last_cbc_opcode != CBC_END)
  {
    parser_flush_cbc (context_p);
  }

  /* Branch opcodes never push anything onto the stack. */
  PARSER_ASSERT ((flags >> CBC_STACK_ADJUST_SHIFT) <= CBC_STACK_ADJUST_BASE
                 && (CBC_STACK_ADJUST_BASE - (flags >> CBC_STACK_ADJUST_SHIFT)) <= context_p->stack_depth);
  context_p->stack_depth += CBC_STACK_ADJUST_VALUE (flags);

#if PARSER_MAXIMUM_CODE_SIZE <= 65535
  opcode++;
#else
  opcode += 2;
#endif /* PARSER_MAXIMUM_CODE_SIZE <= 65535 */

  parser_emit_two_bytes (context_p, opcode, 0);
  branch_p->page_p = context_p->byte_code.last_p;
  branch_p->offset = (context_p->byte_code.last_position - 1) | (context_p->byte_code_size << 8);

#if PARSER_MAXIMUM_CODE_SIZE <= 65535
  PARSER_APPEND_TO_BYTE_CODE (context_p, 0);
  context_p->byte_code_size += 3;
#else
  parser_emit_two_bytes (context_p, 0, 0);
  context_p->byte_code_size += 4;
#endif /* PARSER_MAXIMUM_CODE_SIZE <= 65535 */

#ifdef PARSER_DEBUG
  if (context_p->is_show_opcodes)
  {
    printf (" [%3d] %s\n", (int) context_p->stack_depth, cbc_names[opcode]);
  }
#endif /* PARSER_DEBUG */
} /* parser_emit_cbc_forward_branch */

/**
 * Append a byte code with a branch argument
 */
void
parser_emit_cbc_backward_branch (parser_context *context_p, /**< context */
                                 cbc_opcode opcode, /**< opcode */
                                 uint32_t offset) /**< destination offset */
{
  uint8_t flags = cbc_flags[opcode];

  PARSER_ASSERT (flags & CBC_HAS_BRANCH_ARG);
  PARSER_ASSERT (CBC_BRANCH_IS_BACKWARD (opcode));
  PARSER_ASSERT (CBC_BRANCH_OFFSET_LENGTH (opcode) == 1);

  if (context_p->last_cbc_opcode != CBC_END)
  {
    parser_flush_cbc (context_p);
  }

  PARSER_ASSERT (offset < context_p->byte_code_size);

  offset = context_p->byte_code_size - offset;

  /* Branch opcodes never push anything onto the stack. */
  PARSER_ASSERT ((flags >> CBC_STACK_ADJUST_SHIFT) <= CBC_STACK_ADJUST_BASE
                 && (CBC_STACK_ADJUST_BASE - (flags >> CBC_STACK_ADJUST_SHIFT)) <= context_p->stack_depth);
  context_p->stack_depth += CBC_STACK_ADJUST_VALUE (flags);

  context_p->byte_code_size += 2;
#if PARSER_MAXIMUM_CODE_SIZE <= 65535
  if (offset > 255)
  {
    opcode++;
    context_p->byte_code_size++;
  }
#else
  if (offset > 65535)
  {
    opcode += 2;
    context_p->byte_code_size += 2;
  }
  else if (offset > 255)
  {
    opcode++;
    context_p->byte_code_size++;
  }
#endif

  PARSER_APPEND_TO_BYTE_CODE (context_p, opcode);

#if PARSER_MAXIMUM_CODE_SIZE > 65535
  if (offset > 65535)
  {
    PARSER_APPEND_TO_BYTE_CODE (context_p, offset >> 16);
  }
#endif

  if (offset > 255)
  {
    PARSER_APPEND_TO_BYTE_CODE (context_p, (offset >> 8) & 0xff);
  }

  PARSER_APPEND_TO_BYTE_CODE (context_p, offset & 0xff);

#ifdef PARSER_DEBUG
  if (context_p->is_show_opcodes)
  {
    printf (" [%3d] %s\n", (int) context_p->stack_depth, cbc_names[opcode]);
  }
#endif /* PARSER_DEBUG */
} /* parser_emit_cbc_backward_branch */

#undef PARSER_CHECK_LAST_POSITION
#undef PARSER_APPEND_TO_BYTE_CODE

/**
 * Set a branch to the current byte code position
 */
void
parser_set_branch_to_current_position (parser_context *context_p, /**< context */
                                       parser_branch *branch_p) /**< branch result */
{
  uint32_t delta;
  size_t offset;
  parser_mem_page *page_p = branch_p->page_p;

  if (context_p->last_cbc_opcode != CBC_END)
  {
    parser_flush_cbc (context_p);
  }

  PARSER_ASSERT (context_p->byte_code_size > (branch_p->offset >> 8));

  delta = context_p->byte_code_size - (branch_p->offset >> 8);
  offset = (branch_p->offset & 0xff);

  PARSER_ASSERT (delta <= PARSER_MAXIMUM_CODE_SIZE);

#if PARSER_MAXIMUM_CODE_SIZE <= 65535
  page_p->bytes[offset++] = (delta >> 8);
  if (offset >= PARSER_CBC_STREAM_PAGE_SIZE)
  {
    page_p = page_p->next_p;
    offset = 0;
  }
#else
  page_p->bytes[offset++] = (delta >> 16);
  if (offset >= PARSER_CBC_STREAM_PAGE_SIZE)
  {
    page_p = page_p->next_p;
    offset = 0;
  }
  page_p->bytes[offset++] = ((delta >> 8) & 0xff);
  if (offset >= PARSER_CBC_STREAM_PAGE_SIZE)
  {
    page_p = page_p->next_p;
    offset = 0;
  }
#endif
  page_p->bytes[offset++] = delta & 0xff;
} /* parser_set_branch_to_current_position */
