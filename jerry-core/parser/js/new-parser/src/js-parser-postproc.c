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
 * Compute real literal indicies.
 *
 * @return literal encoding mode.
 */
static cbc_literal_encoding
parser_compute_offsets (parser_context *context_p) /**< context */
{
  parser_list_iterator literal_iterator;
  lexer_literal *literal_p;

  uint16_t var_index = 0;
  uint16_t ident_index = context_p->var_count;
  uint16_t other_index = ident_index + context_p->ident_count;

  parser_list_iterator_init (&context_p->literal_pool, &literal_iterator);
  while ((literal_p = (lexer_literal *) parser_list_iterator_next (&literal_iterator)))
  {
    if (literal_p->type == LEXER_VAR_LITERAL)
    {
      literal_p->index = var_index;
      var_index++;
    }
    else if (literal_p->type == LEXER_IDENT_LITERAL)
    {
      literal_p->index = ident_index;
      ident_index++;
    }
    else
    {
      literal_p->index = other_index;
      other_index++;
    }
  }

  PARSER_ASSERT (var_index == context_p->var_count);
  PARSER_ASSERT (ident_index == context_p->var_count + context_p->ident_count);
  PARSER_ASSERT (other_index == context_p->var_count + context_p->ident_count + context_p->other_count);
  PARSER_ASSERT (other_index <= PARSER_MAXIMUM_NUMBER_OF_LITERALS);

  if (other_index < 256)
  {
    return cbc_literal_encoding_byte;
  }

  if (other_index < 511)
  {
    return cbc_literal_encoding_small;
  }

  return cbc_literal_encoding_full;
}

/*
 * During byte code post processing certain bytes are not
 * copied into the final byte code buffer. For example, if
 * one byte is enough for encoding a literal index, the
 * second byte is not copied. However, when a byte is skipped,
 * the offsets of those branches which crosses (jumps over)
 * that byte code should also be decreased by one. Instead
 * of finding these jumps every time when a byte is skipped,
 * all branch offset updates are computed in one step.
 *
 * Branch offset mapping example:
 *
 * Let's assume that each parser_mem_page of the byte_code
 * buffer is 8 bytes long and only 4 bytes are kept for a
 * given page:
 *
 * +---+---+---+---+---+---+---+---+
 * | X | 1 | 2 | 3 | X | 4 | X | X |
 * +---+---+---+---+---+---+---+---+
 *
 * X marks those bytes which are removed. The resulting
 * offset mapping is the following:
 *
 * +---+---+---+---+---+---+---+---+
 * | 0 | 1 | 2 | 3 | 3 | 4 | 4 | 4 |
 * +---+---+---+---+---+---+---+---+
 *
 * Each X is simply replaced by the index of the previous
 * index starting from zero. This shows the number of
 * copied bytes before a given byte including the byte
 * itself. The last byte always shows the number of bytes
 * copied from this page.
 *
 * This mapping allows recomputing all branch targets,
 * since mapping[to] - mapping[from] is the new argument
 * for forward branches. As for backward branches, the
 * equation is reversed to mapping[from] - mapping[to].
 *
 * The mapping is relative to one page, so distance
 * computation affecting multiple pages requires a loop.
 * We should also note that only argument bytes can
 * be skipped, so removed bytes cannot be targeted by
 * branches. Valid branches always target instruction
 * starts only.
 */

/**
 * Recompute the argument of a forward branch.
 *
 * @return the new distance
 */
static size_t
parser_update_forward_branch (parser_mem_page *page_p, /**< current page */
                              size_t full_distance, /**< full distance */
                              uint8_t bytes_copied_before_jump) /**< bytes copied before jump */
{
  size_t new_distance = 0;

  while (full_distance > PARSER_CBC_STREAM_PAGE_SIZE)
  {
    new_distance += page_p->bytes[PARSER_CBC_STREAM_PAGE_SIZE - 1] & CBC_LOWER_SEVEN_BIT_MASK;
    full_distance -= PARSER_CBC_STREAM_PAGE_SIZE;
    page_p = page_p->next_p;
  }

  new_distance += page_p->bytes[full_distance - 1] & CBC_LOWER_SEVEN_BIT_MASK;
  return new_distance - bytes_copied_before_jump;
} /* parser_update_forward_branch */

/**
 * Recompute the argument of a backward branch.
 *
 * @return the new distance
 */
static size_t
parser_update_backward_branch (parser_mem_page *page_p, /**< current page */
                               size_t full_distance, /**< full distance */
                               uint8_t bytes_copied_before_jump) /**< bytes copied before jump */
{
  size_t new_distance = bytes_copied_before_jump;

  while (full_distance >= PARSER_CBC_STREAM_PAGE_SIZE)
  {
    PARSER_ASSERT (page_p != NULL);
    new_distance += page_p->bytes[PARSER_CBC_STREAM_PAGE_SIZE - 1] & CBC_LOWER_SEVEN_BIT_MASK;
    full_distance -= PARSER_CBC_STREAM_PAGE_SIZE;
    page_p = page_p->next_p;
  }

  if (full_distance > 0)
  {
    size_t offset = PARSER_CBC_STREAM_PAGE_SIZE - full_distance;

    PARSER_ASSERT (page_p != NULL);

    new_distance += page_p->bytes[PARSER_CBC_STREAM_PAGE_SIZE - 1] & CBC_LOWER_SEVEN_BIT_MASK;
    new_distance -= page_p->bytes[offset - 1] & CBC_LOWER_SEVEN_BIT_MASK;
  }

  return new_distance;
} /* parser_update_backward_branch */

/**
 * Update targets of all branches in one step.
 */
static void
parse_update_branches (parser_context *context_p, /**< context */
                       uint8_t *byte_code_p, /**< byte code */
                       size_t length) /**< length of byte code */
{
  parser_mem_page *page_p = context_p->byte_code.first_p;
  parser_mem_page *prev_page_p = NULL;
  parser_mem_page *last_page_p = context_p->byte_code.last_p;
  size_t last_position = context_p->byte_code.last_position;
  size_t offset = 0;
  size_t bytes_copied = 0;

  PARSER_ASSERT (last_page_p != NULL);

  if (last_position >= PARSER_CBC_STREAM_PAGE_SIZE)
  {
    last_page_p = NULL;
    last_position = 0;
  }

  while (page_p != last_page_p || offset < last_position)
  {
    /* Branch instructions are marked to improve search speed. */
    if (page_p->bytes[offset] & CBC_HIGHEST_BIT_MASK)
    {
      uint8_t *bytes_p = byte_code_p + bytes_copied;
      cbc_opcode opcode;
      uint8_t bytes_copied_before_jump = 0;
      size_t branch_argument_length;
      size_t target_distance;

      if (offset > 0)
      {
        bytes_copied_before_jump = page_p->bytes[offset - 1] & CBC_LOWER_SEVEN_BIT_MASK;
      }
      bytes_p += bytes_copied_before_jump;

      opcode = *bytes_p++;
      PARSER_ASSERT (cbc_flags[opcode] & CBC_HAS_BRANCH_ARG);
      branch_argument_length = CBC_BRANCH_OFFSET_LENGTH (opcode);

      /* Decoding target. */
      target_distance = 0;
      do
      {
        target_distance = (target_distance << 8) | *bytes_p;
        bytes_p++;
      }
      while (--branch_argument_length > 0);

      if (CBC_BRANCH_IS_FORWARD (opcode))
      {
        target_distance = parser_update_forward_branch (page_p,
                                                        offset + target_distance,
                                                        bytes_copied_before_jump);
      }
      else
      {
        if (target_distance < offset)
        {
          uint8_t bytes_copied_before_target = page_p->bytes[offset - target_distance - 1];
          target_distance = bytes_copied_before_jump - (bytes_copied_before_target & CBC_LOWER_SEVEN_BIT_MASK);
        }
        else if (target_distance == offset)
        {
          target_distance = bytes_copied_before_jump;
        }
        else
        {
          target_distance = parser_update_backward_branch (prev_page_p,
                                                           target_distance - offset,
                                                           bytes_copied_before_jump);
        }
      }

      /* Encoding target again. */
      branch_argument_length = CBC_BRANCH_OFFSET_LENGTH (opcode);
      do
      {
        bytes_p--;
        *bytes_p = (uint8_t) (target_distance & 0xff);
        target_distance >>= 8;
      }
      while (--branch_argument_length > 0);
    }

    offset++;
    if (offset >= PARSER_CBC_STREAM_PAGE_SIZE)
    {
      parser_mem_page *next_p = page_p->next_p;

      /* We reverse the pages before the current page. */
      page_p->next_p = prev_page_p;
      prev_page_p = page_p;

      bytes_copied += page_p->bytes[PARSER_CBC_STREAM_PAGE_SIZE - 1] & CBC_LOWER_SEVEN_BIT_MASK;
      page_p = next_p;
      offset = 0;
    }
  }

  /* After this point the pages of the byte code stream are
   * not used anymore. However, they needs to be freed during
   * cleanup, so the first and last pointers of the stream
   * descriptor are reversed as well. */
  if (last_page_p != NULL)
  {
    PARSER_ASSERT (last_page_p == context_p->byte_code.last_p);
    last_page_p->next_p = prev_page_p;
  }
  else
  {
    last_page_p = context_p->byte_code.last_p;
  }

  context_p->byte_code.last_p = context_p->byte_code.first_p;
  context_p->byte_code.first_p = last_page_p;
} /* parse_update_branches */

#ifdef PARSER_DEBUG

static void
parse_print_final_cbc (parser_context *context_p, /**< context */
                       uint8_t *byte_code_p, /**< byte code */
                       size_t length, /**< length of byte code */
                       cbc_literal_encoding encoding) /**< literal encoding mode */
{
  cbc_opcode opcode;
  uint8_t flags;
  uint8_t *byte_code_start_p = byte_code_p;
  uint8_t *byte_code_end_p = byte_code_p + length;
  size_t cbc_offset;

  printf ("\nFinal byte code:\n  Maximum stack depth: %d\n", (int) context_p->stack_max_depth);
  printf ("  Literal encoding: ");
  switch (encoding)
  {
    case cbc_literal_encoding_byte:
    {
      printf ("byte\n");
      break;
    }
    case cbc_literal_encoding_small:
    {
      printf ("small\n");
      break;
    }
    case cbc_literal_encoding_full:
    {
      printf ("full\n");
      break;
    }
  }

  printf ("  Number of var literals: %d\n", (int) context_p->var_count);
  printf ("  Number of identifiers: %d\n", (int) context_p->ident_count);
  printf ("  Number of other literals: %d\n\n", (int) context_p->other_count);

  while (byte_code_p < byte_code_end_p)
  {
    opcode = *byte_code_p;
    flags = cbc_flags[opcode];
    cbc_offset = byte_code_p - byte_code_start_p;

    printf (" %3d : %s", (int) cbc_offset, cbc_names[*byte_code_p]);
    byte_code_p++;

    if (flags & CBC_HAS_BYTE_ARG)
    {
      printf (" byte_arg:%d", *byte_code_p);
      byte_code_p++;
    }

    if (flags & CBC_HAS_LITERAL_ARG)
    {
      uint16_t literal_index;
      parser_list_iterator literal_iterator;
      lexer_literal *literal_p;

#if PARSER_MAXIMUM_NUMBER_OF_LITERALS <= CBC_MAXIMUM_BYTE_VALUE
      literal_index = *byte_code_p;
#else
      switch (encoding)
      {
        case cbc_literal_encoding_byte:
        {
          literal_index = *byte_code_p;
          break;
        }
        case cbc_literal_encoding_small:
        {
          literal_index = *byte_code_p;
          if (literal_index == CBC_MAXIMUM_BYTE_VALUE)
          {
            byte_code_p++;
            literal_index = CBC_MAXIMUM_BYTE_VALUE + ((uint16_t) *byte_code_p);
          }
          break;
        }
        case cbc_literal_encoding_full:
        {
          literal_index = *byte_code_p;
          if (literal_index & 0x80)
          {
            byte_code_p++;
            literal_index = ((literal_index & 0x7f) << 8) | ((uint16_t) *byte_code_p);
          }
          break;
        }
      }
#endif /* PARSER_MAXIMUM_NUMBER_OF_LITERALS <= CBC_MAXIMUM_BYTE_VALUE */
      byte_code_p++;

      parser_list_iterator_init (&context_p->literal_pool, &literal_iterator);
      while (1)
      {
        literal_p = (lexer_literal *) parser_list_iterator_next (&literal_iterator);
        PARSER_ASSERT (literal_p != NULL);

        if (literal_p->index == literal_index)
        {
          printf (" ");
          util_print_literal (literal_p);
          printf ("-id:%d", literal_index);
          break;
        }
      }
    }

    if (flags & CBC_HAS_BRANCH_ARG)
    {
      size_t branch_offset_length = CBC_BRANCH_OFFSET_LENGTH (opcode);
      size_t offset = 0;

      do
      {
        offset = (offset << 8) | *byte_code_p++;
      }
      while (--branch_offset_length > 0);

      if (CBC_BRANCH_IS_FORWARD (opcode))
      {
        printf (" offset:%d(->%d)", (int) offset, (int) (cbc_offset + offset));
      }
      else
      {
        printf (" offset:%d(->%d)", (int) offset, (int) (cbc_offset - offset));
      }
    }
    printf ("\n");
  }
} /* parse_print_final_cbc */

#endif /* PARSER_DEBUG */

#define PARSER_NEXT_BYTE(page_p, offset) \
  do { \
    if (++(offset) >= PARSER_CBC_STREAM_PAGE_SIZE) \
    { \
      offset = 0; \
      page_p = page_p->next_p; \
    } \
  } while (0)

#define PARSER_NEXT_BYTE_UPDATE(page_p, offset, real_offset) \
  do { \
    page_p->bytes[offset] = real_offset; \
    if (++(offset) >= PARSER_CBC_STREAM_PAGE_SIZE) \
    { \
      offset = 0; \
      real_offset = 0; \
      page_p = page_p->next_p; \
    } \
  } while (0)

/**
 * Post processing main function.
 */
void
parser_post_processing (parser_context *context_p) /**< context */
{
  cbc_literal_encoding encoding;
  parser_mem_page *page_p;
  parser_mem_page *last_page_p = context_p->byte_code.last_p;
  size_t last_position = context_p->byte_code.last_position;
  size_t offset;
  size_t length;
  uint8_t real_offset;
  uint8_t *byte_code_p;
  uint8_t *dst_p;

  encoding = parser_compute_offsets (context_p);

  if (last_position >= PARSER_CBC_STREAM_PAGE_SIZE)
  {
    last_page_p = NULL;
    last_position = 0;
  }

  page_p = context_p->byte_code.first_p;
  offset = 0;
  length = 0;

  while (page_p != last_page_p || offset < last_position)
  {
    cbc_opcode opcode;
    uint8_t flags;

    opcode = page_p->bytes[offset];
    flags = cbc_flags[opcode];
    PARSER_NEXT_BYTE (page_p, offset);
    length++;

    if (flags & CBC_HAS_BYTE_ARG)
    {
      /* This argument will be copied without modification. */
      PARSER_NEXT_BYTE (page_p, offset);
      length++;
    }

    if (flags & CBC_HAS_LITERAL_ARG)
    {
#if PARSER_MAXIMUM_NUMBER_OF_LITERALS <= CBC_MAXIMUM_BYTE_VALUE
      size_t literal_index = page_p->bytes[offset];

      PARSER_ASSERT (encoding == cbc_literal_encoding_byte);
      lexer_literal *literal_p = parser_list_get (&context_p->literal_pool, literal_index);
      page_p->bytes[offset] = (uint8_t) literal_p->index;

      PARSER_NEXT_BYTE (page_p, offset);
      length++;
#else
      uint8_t *first_byte = page_p->bytes + offset;

      PARSER_NEXT_BYTE (page_p, offset);
      length++;

      if (encoding == cbc_literal_encoding_byte)
      {
        size_t literal_index = *first_byte;

        PARSER_ASSERT (page_p->bytes[offset] == 0);
        lexer_literal *literal_p = parser_list_get (&context_p->literal_pool, literal_index);
        *first_byte = (uint8_t) literal_p->index;
      }
      else
      {
        size_t literal_index = ((size_t) *first_byte) | (((size_t) page_p->bytes[offset]) << 8);
        lexer_literal *literal_p = parser_list_get (&context_p->literal_pool, literal_index);

        if (encoding == cbc_literal_encoding_small)
        {
          if (literal_index < CBC_MAXIMUM_BYTE_VALUE)
          {
            *first_byte = (uint8_t) literal_p->index;
            page_p->bytes[offset] = 0;
          }
          else
          {
            PARSER_ASSERT (literal_index <= 511);
            *first_byte = CBC_MAXIMUM_BYTE_VALUE;
            page_p->bytes[offset] = (uint8_t) (literal_p->index - CBC_MAXIMUM_BYTE_VALUE);
            length++;
          }
        }
        else
        {
          if (literal_index < 128)
          {
            *first_byte = (uint8_t) literal_p->index;
            page_p->bytes[offset] = 0;
          }
          else
          {
            PARSER_ASSERT (literal_index <= 32767);
            *first_byte = (uint8_t) (literal_p->index >> 8) | 0x80;
            page_p->bytes[offset] = (uint8_t) (literal_p->index & 0xff);
            length++;
          }
        }
      }
      PARSER_NEXT_BYTE (page_p, offset);
#endif /* PARSER_MAXIMUM_NUMBER_OF_LITERALS <= CBC_MAXIMUM_BYTE_VALUE */
    }

    if (flags & CBC_HAS_BRANCH_ARG)
    {
      size_t branch_offset_length = CBC_BRANCH_OFFSET_LENGTH (opcode) - 1;
      int prefix_zero = 1;

      /* The leading zeroes are dropped from the stream.
       * Although dropping these zeroes for backward
       * branches are unnecessary, we use the same
       * code path for simplicity. */
      while (branch_offset_length > 0)
      {
        uint8_t byte = page_p->bytes[offset];
        if (byte > 0 || !prefix_zero)
        {
          prefix_zero = 0;
          length++;
        }
        else
        {
          PARSER_ASSERT (CBC_BRANCH_IS_FORWARD (opcode));
        }
        PARSER_NEXT_BYTE (page_p, offset);
        branch_offset_length--;
      }

      /* Last byte is always copied. */
      PARSER_NEXT_BYTE (page_p, offset);
      length++;
    }
  }

  byte_code_p = (uint8_t *) parser_malloc (context_p, length);
  dst_p = byte_code_p;

  page_p = context_p->byte_code.first_p;
  offset = 0;
  real_offset = 0;

  while (page_p != last_page_p || offset < last_position)
  {
    uint8_t flags;
    uint8_t *current_cbc_opcode;

    current_cbc_opcode = dst_p;
    *dst_p++ = page_p->bytes[offset];
    flags = cbc_flags[page_p->bytes[offset]];

    /* Storing where the current byte is mapped. */
    real_offset++;
    if (flags & CBC_HAS_BRANCH_ARG)
    {
      real_offset |= 0x80;
    }
    PARSER_NEXT_BYTE_UPDATE (page_p, offset, real_offset);
    if (flags & CBC_HAS_BRANCH_ARG)
    {
      real_offset &= ~0x80;
    }

    /* Only literal and call arguments can be combined. */
    PARSER_ASSERT (!(flags & CBC_HAS_BRANCH_ARG)
                   || !(flags & (CBC_HAS_BYTE_ARG | CBC_HAS_LITERAL_ARG)));

    if (flags & CBC_HAS_BYTE_ARG)
    {
      /* This argument will be copied without modification. */
      *dst_p++ = page_p->bytes[offset];
      real_offset++;
      PARSER_NEXT_BYTE_UPDATE (page_p, offset, real_offset);
    }

    if (flags & CBC_HAS_LITERAL_ARG)
    {
#if PARSER_MAXIMUM_NUMBER_OF_LITERALS <= CBC_MAXIMUM_BYTE_VALUE
      *dst_p++ = page_p->bytes[offset];
      real_offset++;
      PARSER_NEXT_BYTE_UPDATE (page_p, offset, real_offset);
#else
      uint8_t first_byte = page_p->bytes[offset];

      *dst_p++ = first_byte;
      real_offset++;
      PARSER_NEXT_BYTE_UPDATE (page_p, offset, real_offset);

      if (encoding != cbc_literal_encoding_byte)
      {
        if ((encoding == cbc_literal_encoding_small && first_byte == CBC_MAXIMUM_BYTE_VALUE)
            || (encoding == cbc_literal_encoding_full && (first_byte & 0x80)))
        {
          *dst_p++ = page_p->bytes[offset];
          real_offset++;
        }
      }
      PARSER_NEXT_BYTE_UPDATE (page_p, offset, real_offset);
#endif /* PARSER_MAXIMUM_NUMBER_OF_LITERALS <= CBC_MAXIMUM_BYTE_VALUE */
    }

    if (flags & CBC_HAS_BRANCH_ARG)
    {
      size_t branch_offset_length = CBC_BRANCH_OFFSET_LENGTH (*current_cbc_opcode) - 1;
      int prefix_zero = 1;

      /* The leading zeroes are dropped from the stream. */
      while (branch_offset_length > 0)
      {
        uint8_t byte = page_p->bytes[offset];
        if (byte > 0 || !prefix_zero)
        {
          prefix_zero = 0;
          *dst_p++ = page_p->bytes[offset];
          real_offset++;
        }
        else
        {
          /* When a leading zero is dropped, the branch
           * argument length must be decreased as well. */
          (*current_cbc_opcode)--;
        }
        PARSER_NEXT_BYTE_UPDATE (page_p, offset, real_offset);
        branch_offset_length--;
      }

      PARSER_ASSERT (page_p->bytes[offset] != 0
                     || CBC_BRANCH_OFFSET_LENGTH (*current_cbc_opcode) != 1);
      *dst_p++ = page_p->bytes[offset];
      real_offset++;
      PARSER_NEXT_BYTE_UPDATE (page_p, offset, real_offset);
    }
  }

  PARSER_ASSERT (dst_p == byte_code_p + length);

  parse_update_branches (context_p, byte_code_p, length);

#ifdef PARSER_DEBUG
  if (context_p->is_show_opcodes)
  {
    parse_print_final_cbc (context_p, byte_code_p, length, encoding);
  }
#endif

  printf ("\nParse successfully completed. Total byte code size: %d bytes\n", (int) length);
} /* parser_post_processing */

#undef PARSER_NEXT_BYTE
#undef PARSER_NEXT_BYTE_UPDATE
