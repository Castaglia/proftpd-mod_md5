/*
 * ProFTPD: mod_md5 -- an FSIO module for automatically generating MD5 hashes
 *                     of uploaded files
 *
 * Copyright (c) 2001-2013 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, TJ Saunders gives permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 *
 * This is mod_md5, contrib software for proftpd 1.2.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.  This module
 * is based on a patch from Bill Fenner.
 *
 * $Id: mod_md5.c,v 1.8 2009/09/28 18:56:11 tj Exp tj $
 */

#include "conf.h"

#define MOD_MD5_VERSION 	"mod_md5/0.3.6"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030301
# error "ProFTPD 1.3.3rc1 or later required"
#endif

#if defined(PR_USE_OPENSSL)
# include <openssl/md5.h>
#else
/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991.
 *  All rights reserved.
 *
 * License to copy and use this software is granted provided that it
 * is identified as the "RSA Data Security, Inc. MD5 Message-Digest
 * Algorithm" in all material mentioning or referencing this software
 * or this function.
 *
 * License is also granted to make and use derivative works provided
 * that such works are identified as "derived from the RSA Data
 * Security, Inc. MD5 Message-Digest Algorithm" in all material
 * mentioning or referencing the derived work.
 *
 * RSA Data Security, Inc. makes no representations concerning either
 * the merchantability of this software or the suitability of this
 * software for any particular purpose. It is provided "as is"
 * without express or implied warranty of any kind.
 *
 * These notices must be retained in any copies of any part of this
 * documentation and/or software.
 */

/* MD5 context */
typedef struct {

  /* state (ABCD) */
  uint32_t state[4];

  /* number of bits, module 2^64 (LSB first) */
  uint32_t count[2];

  /* input buffer */
  unsigned char buffer[64];
} MD5_CTX;

static void MD5_Init(MD5_CTX *);
static void MD5_Update(MD5_CTX *, unsigned char *, size_t);
static void MD5_Final(unsigned char *, MD5_CTX *);
#endif /* !PR_USE_OPENSSL */

/* structure for carrying around MD5 data */
struct md5_data {

  /* Path being written */
  char path[PR_TUNABLE_PATH_MAX];

  /* MD5 context */
  MD5_CTX context;

  /* MD5 digest */
  unsigned char digest[16];

  /* ASCII representation of the digest, with space for terminating NUL */
  unsigned char ascii_digest[33];
};

static int md5_engine = FALSE;

/* Pointer to the source path for renames. */
static const char *rnfr_path = NULL;

/* Scratchwork buffer */
static char pathbuf[PR_TUNABLE_PATH_MAX];

static const char *trace_channel = "md5";

/* Support routines
 */

static char *add_md5_ext(const char *path) {
  char *ptr = NULL;

  /* Clear the scratchpad.  Automatically add a ".md5" extension to
   * the path being opened.
   */
  memset(pathbuf, '\0', sizeof(pathbuf));
  sstrcat(pathbuf, path, sizeof(pathbuf));

  /* Watch out for "." and ".." */
  if (strcmp(path, ".") == 0 ||
      strcmp(path, "..") == 0)
    return pathbuf;

  /* Also, watch out for paths that already have the ".md5" extension.
   * As there isn't a nice strrstr() library function, this is a little
   * messy.  Find the end of the given path, back up four characters, and
   * match strings.
   */
  ptr = &(pathbuf[strlen(pathbuf) - 4]);
  if (strcmp(ptr, ".md5") == 0)
    return pathbuf;

  sstrcat(pathbuf, ".md5", sizeof(pathbuf));
  return pathbuf;
}

#if !defined(PR_USE_OPENSSL)
/* NOTE: these MD5 routines are taken from RFC 1321 */

/* Constants for MD5_Transform routine.
 */

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

static void MD5_Transform(uint32_t *, unsigned char[64]);
static void Encode(unsigned char *, uint32_t *, unsigned int);
static void Decode(uint32_t *, unsigned char *, unsigned int);

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

/* MD5 initialization. Begins an MD5 operation, writing a new context.
 */
static void MD5_Init(MD5_CTX *context) {
  context->count[0] = context->count[1] = 0;

  /* Load magic initialization constants.
   */
  context->state[0] = 0x67452301;
  context->state[1] = 0xefcdab89;
  context->state[2] = 0x98badcfe;
  context->state[3] = 0x10325476;
}

/* MD5 block update operation. Continues an MD5 message-digest
 * operation, processing another message block, and updating the
 * context.
 */
static void MD5_Update(MD5_CTX *context, unsigned char *input,
    size_t inputLen) {
  unsigned int i, idx, partLen;

  /* Compute number of bytes mod 64 */
  idx = (unsigned int)((context->count[0] >> 3) & 0x3F);

  /* Update number of bits */
  if ((context->count[0] += ((uint32_t)inputLen << 3))
       < ((uint32_t)inputLen << 3))
    context->count[1]++;
  context->count[1] += ((uint32_t)inputLen >> 29);

  partLen = 64 - idx;

  /* Transform as many times as possible */
  if (inputLen >= partLen) {
    memcpy((unsigned char *) &context->buffer[idx],
      (unsigned char *) input, partLen);
    MD5_Transform(context->state, context->buffer);

    for (i = partLen; i + 63 < inputLen; i += 64)
      MD5_Transform(context->state, &input[i]);

    idx = 0;

  } else
    i = 0;

  /* Buffer remaining input */
  memcpy((unsigned char *) &context->buffer[idx],
    (unsigned char *) &input[i], inputLen-i);
}

/* MD5 finalization. Ends an MD5 message-digest operation, writing the
 * the message digest and zeroizing the context.
 */
static void MD5_Final(unsigned char *digest, MD5_CTX *context) {
  unsigned char bits[8];
  unsigned int idx;
  size_t padLen;

  /* Save number of bits */
  Encode (bits, context->count, 8);

  /* Pad out to 56 mod 64.
   */
  idx = (unsigned int) ((context->count[0] >> 3) & 0x3f);
  padLen = (idx < 56) ? (56 - idx) : (120 - idx);
  MD5_Update(context, PADDING, padLen);

  /* Append length (before padding) */
  MD5_Update(context, bits, 8);

  /* Store state in digest */
  Encode(digest, context->state, 16);

  /* Zeroize sensitive information.
   */
  memset((unsigned char *) context, 0, sizeof(*context));
}

/* MD5 basic transformation. Transforms state based on block.
 */
static void MD5_Transform(uint32_t state[4], unsigned char block[64]) {
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];

  Decode(x, block, 64);

  /* Round 1 */
  FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
  FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
  FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
  FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
  FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
  FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
  FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
  FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
  FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
  FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
  FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
  FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
  FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
  FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
  FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
  FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

 /* Round 2 */
  GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
  GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
  GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
  GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
  GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
  GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
  GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
  GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
  GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
  GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
  GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */

  GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
  GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
  GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
  GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
  GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

  /* Round 3 */
  HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
  HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
  HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
  HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
  HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
  HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
  HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
  HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
  HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
  HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
  HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
  HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
  HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
  HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
  HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
  HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

  /* Round 4 */
  II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
  II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
  II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
  II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
  II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
  II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
  II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
  II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
  II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
  II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
  II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
  II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
  II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
  II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
  II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
  II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  /* Zeroize sensitive information.
   */
  memset((unsigned char *) x, 0, sizeof(x));
}

/* Encodes input (unsigned long) into output (unsigned char). Assumes len is
 * a multiple of 4.
 */
static void Encode(unsigned char *output, uint32_t *input, unsigned int len) {
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = (unsigned char)(input[i] & 0xff);
    output[j+1] = (unsigned char)((input[i] >> 8) & 0xff);
    output[j+2] = (unsigned char)((input[i] >> 16) & 0xff);
    output[j+3] = (unsigned char)((input[i] >> 24) & 0xff);
  }
}

/* Decodes input (unsigned char) into output (unsigned long). Assumes len is
 * a multiple of 4.
 */
static void Decode(uint32_t *output, unsigned char *input, unsigned int len) {
  unsigned int i, j;

  for (i = 0, j = 0; j < len; i++, j += 4)
    output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j+1]) << 8) |
    (((uint32_t)input[j+2]) << 16) | (((uint32_t)input[j+3]) << 24);
}

#endif /* !PR_USE_OPENSSL */

/* FSIO callbacks
 */

static int md5_close_cb(pr_fh_t *fh, int fd) {
  int write_md5 = FALSE;

  if (session.curr_cmd != NULL) {
    const char *proto = pr_session_get_protocol(0);

    /* Need to check for slightly different commands if mod_sftp is doing
     * the writing.
     */
    if (strncmp(proto, "sftp", 5) != 0) {
      /* For FTP/FTPS, we only need check for STOR/STOU here. */
      if (strncmp(session.curr_cmd, C_STOR, 5) == 0 ||
          strncmp(session.curr_cmd, C_STOU, 5) == 0) {
        write_md5 = TRUE;
      }

    } else {
      /* For SFTP sessions, we need to check for STOR, STOU, and WRITE. */
      if (strncmp(session.curr_cmd, C_STOR, 5) == 0 ||
          strncmp(session.curr_cmd, C_STOU, 5) == 0 ||
          strncmp(session.curr_cmd, "WRITE", 6) == 0) {
        write_md5 = TRUE;
      }
    }

    pr_trace_msg(trace_channel, 9, "protocol %s, command %s, write md5 = %s",
      proto, session.curr_cmd, write_md5 ? "true" : "false");
  }

  if (write_md5) {
    register int i = 0;
    FILE *md5f = NULL;
    struct md5_data *data;

    data = (struct md5_data *) fh->fh_data;

    /* Finalize the MD5 context, extract the digests, close the file. */
    MD5_Final(data->digest, &(data->context));

    /* Extract an ASCII representation of the digest. */
    for (i = 0; i < sizeof(data->digest); i++) {
      sprintf((char *) &(data->ascii_digest[i*2]), "%02x", data->digest[i]);
    }

    md5f = fopen(add_md5_ext(data->path), "w");
    if (md5f == NULL) {
      pr_log_pri(PR_LOG_INFO, MOD_MD5_VERSION ": unable to open '%s': %s", 
        add_md5_ext(data->path), strerror(errno));

    } else {
      char *tmp = strrchr(data->path, '/');

      /* Write out the .md5 file: <hash>  <filename>.  Print out just the
       * filename, not the full path.
       */
      fprintf(md5f, "%s  %s\n", data->ascii_digest, tmp ? tmp + 1 : data->path);
      fclose(md5f);
      md5f = NULL;
    }
  }

  return close(fd);
}

static int md5_open_cb(pr_fh_t *fh, const char *path, int flags) {

  if (session.curr_cmd != NULL &&
      (strcmp(session.curr_cmd, C_STOR) == 0 ||
       strcmp(session.curr_cmd, C_STOU) == 0)) {
    struct md5_data *data;

    /* Open the file for reading, and clear and initialize the MD5 context
     * and digest buffers
     */

    data = pcalloc(fh->fh_pool, sizeof(struct md5_data));

    MD5_Init(&(data->context));
    memset(data->digest, 0, sizeof(data->digest));
    memset(data->ascii_digest, 0, sizeof(data->ascii_digest));
    fh->fh_data = data;

    /* Store the filename being written */
    sstrncpy(data->path, path, sizeof(data->path));
  }

  return open(path, flags, PR_OPEN_MODE);
}

static int md5_unlink_cb(pr_fs_t *fs, const char *path) {

  /* Remove the associated .md5 file as well */
  unlink(add_md5_ext(path));

  return unlink(path);
}

static int md5_write_cb(pr_fh_t *fh, int fd, const char *buf, size_t buflen) {
  int update_md5 = FALSE;
  const char *proto;

  proto = pr_session_get_protocol(0);

  /* Need to check for slightly different commands if mod_sftp is doing the
   * writing.
   */
  if (strcmp(proto, "sftp") != 0) {
    if (session.curr_cmd != NULL &&
        (strcmp(session.curr_cmd, C_STOR) == 0 ||
         strcmp(session.curr_cmd, C_STOU) == 0)) {
      update_md5 = TRUE;
    }

  } else {
    update_md5 = TRUE;
  }

  if (update_md5) {
    struct md5_data *data;

    /* Update the MD5 digest with the data, and write it to the file */

    data = (struct md5_data *) fh->fh_data;
    MD5_Update(&(data->context), (unsigned char *) buf, buflen);
  }

  return write(fd, buf, buflen);
}

/* Utility functions
 */

static int is_md5_path(pool *p, const char *path) {
  pr_fs_t *fs;

  pr_fs_clear_cache();
  fs = pr_get_fs(path, NULL);

  if (fs != NULL) {
    if (strcmp(fs->fs_name, "md5") == 0) {
      return 0;
    }
  }

  errno = EPERM;
  return -1;
}

static int write_digest_file(pool *p, const char *path) {
  MD5_CTX context;
  FILE *fh = NULL;
  unsigned char digest[16];
  char ascii_digest[33] = {'\0'};
  register int i = 0;

  path = dir_realpath(p, path);

  fh = fopen(path, "rb");
  if (fh == NULL) {
    int xerrno = errno;
    pr_log_pri(PR_LOG_NOTICE, MOD_MD5_VERSION ": unable to open '%s': %s",
      path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  /* Now, since the file changed, the .md5 file needs to be redone.  This
   * will require re-digesting the entire file.  Oh well.
   */
  MD5_Init(&context);

  while (!feof(fh)) { 
    unsigned char buf[2048];
    int buflen;

    pr_signals_handle();
 
    memset(buf, 0, sizeof(buf));
    buflen = fread(buf, sizeof(char), sizeof(buf), fh);
    if (buflen > 0)
      MD5_Update(&context, buf, buflen);
  }
  fclose(fh);
  fh = NULL;

  memset(digest, 0, sizeof(digest));
  MD5_Final(digest, &context);

  /* Extract an ASCII representation of the digest */
  for (i = 0; i < sizeof(digest); i++)
    sprintf(&(ascii_digest[i*2]), "%02x", digest[i]);

  fh = fopen(add_md5_ext(path), "w");
  if (fh == NULL) {
    int xerrno = errno;

    pr_log_pri(PR_LOG_INFO, MOD_MD5_VERSION ": unable to open '%s': %s",
        add_md5_ext(path), strerror(xerrno));

    errno = xerrno;
    return -1;

  } else {
    char *tmp = strrchr(path, '/');

    /* Write out the .md5 file:
     *
     *  <hash>  <filename>
     *
     * Use the filename, not the full path.
     */

    fprintf(fh, "%s  %s\n", ascii_digest, tmp ? tmp + 1 : path);
    if (fclose(fh) < 0) {
      int xerrno = errno;

      pr_log_pri(PR_LOG_INFO, MOD_MD5_VERSION ": unable to write '%s': %s",
          add_md5_ext(path), strerror(xerrno));

      errno = xerrno;
      return -1;
    }
  }

  return 0;
}

/* Configuration directive handlers
 */

/* usage: MD5Engine on|off */
MODRET set_md5engine(cmd_rec *cmd) {
  int bool = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  bool = get_boolean(cmd, 1);
  if (bool == -1)
    CONF_ERROR(cmd, "expected Boolean parameter");

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = bool;

  return PR_HANDLED(cmd);
}

/* usage: MD5Path path|"none" */
MODRET set_md5path(cmd_rec *cmd) {
  char *path = NULL;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL|CONF_ANON);

  /* Make sure this is an acceptable path */
  if (*cmd->argv[1] == '.' && *cmd->argv[1] == '.')
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'..' prefix not allowed in path: ",
      cmd->argv[1], NULL));

  if (strpbrk(cmd->argv[1], "*?"))
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "wildcards not allowed in path: ",
      cmd->argv[1], NULL));

  /* Make sure the given path ends in a slash -- very important! */
  path = cmd->argv[1];
  if (path[strlen(path) - 1] != '/')
    path = pstrcat(cmd->tmp_pool, path, "/", NULL);

  c = add_config_param_str(cmd->argv[0], 1, path);
  c->flags |= CF_MERGEDOWN_MULTI;

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET md5_pre_appe(cmd_rec *cmd) {
  char *path;

  if (!md5_engine)
    return PR_DECLINED(cmd);

  path = pr_fs_decode_path(cmd->tmp_pool, cmd->arg);

  /* First make sure that the RNTO path is inside of an MD5Path. */
  if (is_md5_path(cmd->tmp_pool, path) < 0)
    return PR_DECLINED(cmd);

  return PR_DECLINED(cmd);
}

MODRET md5_log_appe(cmd_rec *cmd) {
  char *path;

  if (!md5_engine)
    return PR_DECLINED(cmd);

  path = pr_fs_decode_path(cmd->tmp_pool, cmd->arg);

  /* First make sure that the RNTO path is inside of an MD5Path. */
  if (is_md5_path(cmd->tmp_pool, path) < 0)
    return PR_DECLINED(cmd);

  (void) write_digest_file(cmd->tmp_pool, path);
  return PR_DECLINED(cmd);
}

MODRET md5_post_pass(cmd_rec *cmd) {
  config_rec *c = NULL;

  if (!md5_engine)
    return PR_DECLINED(cmd);

  c = find_config(TOPLEVEL_CONF, CONF_PARAM, "MD5Path", FALSE);
  while (c) {
    int negated = FALSE;
    char *path = c->argv[0];
    pr_fs_t *fs = NULL;

    pr_signals_handle();

    if (*path == '!') {
      negated = TRUE;
      path++;
    }

    /* Check the configured path against the chroot, if any. */
    if (session.chroot_path != NULL) {
      size_t chroot_pathlen;

      chroot_pathlen = strlen(session.chroot_path);
      path = dir_canonical_vpath(cmd->tmp_pool, path);

      if (strncmp(session.chroot_path, path, chroot_pathlen) == 0) {
        path += chroot_pathlen;
      }
    }

    fs = pr_register_fs(cmd->server->pool, "md5", path);
    if (fs == NULL) {
      pr_log_pri(PR_LOG_NOTICE, MOD_MD5_VERSION
        ": notice: unable to register 'md5' fs for path '%s': %s",
          path, strerror(errno));
      c = find_config_next(c, c->next, CONF_PARAM, "MD5Path", FALSE);
      continue;

    } else {
      pr_log_debug(DEBUG8, MOD_MD5_VERSION
        ": registered MD5 FSIO callbacks for path '%s'", path);
    }

    if (!negated) {
      /* Add the custom FS functions here.  All other non-specified
       * functions will default to the system version, which is fine.
       */
      fs->close = md5_close_cb;
      fs->open = md5_open_cb;
      fs->unlink = md5_unlink_cb;
      fs->write = md5_write_cb;

    } else {

      /* A negated path is used to disable the MD5 capabitilies for 
       * subdirectories whose parent directories may be MD5Paths.  To
       * disable the MD5 capabilities, we simply do not set the FSIO
       * function pointers.  To further indicate this, we twiddle the
       * registered fs's name to say 'system'.
       */

      fs->fs_name = pstrdup(fs->fs_pool, "system");
    }

    c = find_config_next(c, c->next, CONF_PARAM, "MD5Path", FALSE);
  }

  /* After registering our paths, we need to make sure that the paths
   * in the FSIO map are properly resolved.  That is, one can configure
   * a MD5Path that starts with a ~, and that ~ needs to be resolved.
   */
  pr_resolve_fs_map();

  return PR_DECLINED(cmd);
}

MODRET md5_pre_rnto(cmd_rec *cmd) {
  if (!md5_engine)
    return PR_DECLINED(cmd);

  if (session.xfer.path) {
    /* Make a copy of the source path for the rename, which is stashed in
     * session.xfer.path.  That memory location is overwritten in the
     * RNTO CMD handler.
     */
    rnfr_path = pstrdup(session.pool, session.xfer.path);
  }

  return PR_DECLINED(cmd);
}

MODRET md5_log_rnto(cmd_rec *cmd) {
  char *full_path, *path;

  if (!md5_engine)
    return PR_DECLINED(cmd);

  if (rnfr_path) {

    /* If the source path is inside an MD5Path, remove any digest file
     * associated with that path.
     */
    if (is_md5_path(cmd->tmp_pool, rnfr_path) == 0) {
      char *rnfr_digest_path;

      rnfr_digest_path = pstrdup(cmd->tmp_pool, add_md5_ext(rnfr_path));
      pr_fsio_unlink(rnfr_digest_path);
      rnfr_path = NULL;
    }
  }

  path = pr_fs_decode_path(cmd->tmp_pool, cmd->arg);

  /* Make sure that the destination path is inside of an MD5Path. */
  pr_fs_clear_cache();
  full_path = dir_realpath(cmd->tmp_pool, path);

  if (is_md5_path(cmd->tmp_pool, full_path) < 0)
    return PR_DECLINED(cmd);

  (void) write_digest_file(cmd->tmp_pool, path);
  return PR_DECLINED(cmd);
}

MODRET md5_site(cmd_rec *cmd) {
  if (!md5_engine)
    return PR_DECLINED(cmd);

  /* Make sure it's a valid SITE MD5 command */
  if (cmd->argc < 3)
    return PR_DECLINED(cmd);

  if (strcasecmp(cmd->argv[1], "MD5") == 0) {
    struct stat st;
    MD5_CTX ctx;
    FILE *md5f = NULL;
    unsigned char digest[16] = {'\0'};
    char ascii_digest[33] = {'\0'}, *cmd_name, *md5_path = NULL, *arg = "";
    register int i = 0;
    unsigned char *authenticated = get_param_ptr(cmd->server->conf,
      "authenticated", FALSE);

    /* The user is required to be authenticated first */
    if (!authenticated ||
        *authenticated == FALSE) {
      pr_response_send(R_530, _("Please login with USER and PASS"));
      return PR_ERROR(cmd);
    }

    /* Construct the target file name by concatenating all the parameters
     * after the "MD5", separating them with spaces.
     */
    for (i = 2; i < cmd->argc; i++) {
      arg = pstrcat(cmd->tmp_pool, arg, *arg ? " " : "", cmd->argv[i], NULL);
    }

    md5_path = session.chroot_path ? arg :
      dir_abs_path(cmd->tmp_pool, arg, TRUE);

    cmd_name = cmd->argv[0];
    cmd->argv[0] = "SITE_MD5";

    /* Check for <Limit> restrictions */
    if (!dir_check(cmd->tmp_pool, cmd, G_READ, md5_path, NULL)) {
      pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(EPERM));
      cmd->argv[0] = cmd_name;
      return PR_ERROR(cmd);
    }

    cmd->argv[0] = cmd_name;

    /* Check if the requested file is a regular file, and nothing else. */
    if (pr_fsio_lstat(md5_path, &st) < 0) {
      pr_response_add_err(R_550, "%s: %s", cmd->arg, strerror(errno));
      return PR_ERROR(cmd);
    }

    if (!S_ISREG(st.st_mode)) {
      pr_response_add_err(R_550, _("%s: not a regular file"), cmd->arg);
      return PR_ERROR(cmd);
    }

    /* If DefaultRoot is in effect, use the relative path, otherwise, use
     * the full path.
     */
    md5f = fopen(md5_path, "rb");
    if (md5f == NULL) {
      pr_response_add(R_202, "%s: %s", cmd->arg, strerror(errno));
      return PR_HANDLED(cmd);
    }

    /* Generate the MD5 digest of the requested file */
    MD5_Init(&ctx);

    while (!feof(md5f)) {
      unsigned char buf[2048];
      size_t buflen;

      pr_signals_handle();

      memset(buf, 0, sizeof(buf));
      buflen = fread(buf, sizeof(unsigned char), sizeof(buf), md5f);
      if (buflen > 0)
        MD5_Update(&ctx, buf, buflen);
    }
    fclose(md5f);
    md5f = NULL;

    MD5_Final(digest, &ctx);

    for (i = 0; i < sizeof(digest); i++)
      sprintf(&(ascii_digest[i*2]), "%02x", digest[i]);
 
    pr_response_add(R_200, "%s\t%s", ascii_digest, arg);

    /* Add one final line to preserve the spacing */
    pr_response_add(R_DUP, _("Please contact %s if this digest is inaccurate"),
      cmd->server->ServerAdmin ? cmd->server->ServerAdmin : "ftp-amdin");

    return PR_HANDLED(cmd);
  }

  if (strcasecmp(cmd->argv[1], "HELP") == 0) {

    /* Add a description of SITE MD5 to the output */
    pr_response_add(R_214, "MD5 <file>");
  }

  return PR_DECLINED(cmd);
}

/* Initialization routines
 */

static int md5_sess_init(void) {
  config_rec *c;

  md5_engine = FALSE;

  c = find_config(main_server->conf, CONF_PARAM, "MD5Engine", FALSE);
  if (c &&
      *((int *) c->argv[0]) == TRUE) {
    md5_engine = TRUE;
  }

  return 0;
}

/* Module API tables
 */

static conftable md5_conftab[] = {
  { "MD5Engine",	set_md5engine,	NULL },
  { "MD5Path",		set_md5path,	NULL },
  { NULL }
};

static cmdtable md5_cmdtab[] = {
  { PRE_CMD,		C_APPE,	G_NONE,	md5_pre_appe,	TRUE, FALSE },
  { LOG_CMD,		C_APPE,	G_NONE,	md5_log_appe,	TRUE, FALSE },
  { POST_CMD,		C_PASS,	G_NONE, md5_post_pass,	FALSE, FALSE },
  { PRE_CMD,		C_RNTO, G_NONE,	md5_pre_rnto,	TRUE, FALSE },
  { POST_CMD,		C_RNTO, G_NONE,	md5_log_rnto,	TRUE, FALSE },
  { CMD,		C_SITE,	G_READ,	md5_site,	TRUE, FALSE },
  { 0, NULL }
};

module md5_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "md5",

  /* Module configuration handler table */
  md5_conftab,

  /* Module command handler table */
  md5_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  NULL,

  /* Session initialization function */
  md5_sess_init,

  /* Module version */
  MOD_MD5_VERSION
};
