/*
 * Copyright (C) 2017  Andrew Gunnerson <andrewgunnerson@gmail.com>
 *
 * This file is part of MultiBootPatcher
 *
 * MultiBootPatcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MultiBootPatcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MultiBootPatcher.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "mbbootimg/guard_p.h"

#ifdef __cplusplus
#  include <cstddef>
#else
#  include <stddef.h>
#endif

#include "mbcommon/common.h"

MB_BEGIN_C_DECLS

struct MbFile;

int _mb_bi_read_fully(struct MbFile *file, void *buf, size_t size,
                      size_t *bytes_read);
int _mb_bi_write_fully(struct MbFile *file, const void *buf, size_t size,
                       size_t *bytes_written);

MB_END_C_DECLS
