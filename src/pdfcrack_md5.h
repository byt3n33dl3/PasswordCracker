/**
 * Copyright (c) 2024 magnum
 * Copyright (c) 2006 Henning Norén
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef __PDFCRACK_MD5_
#define __PDFCRACK_MD5_

#include <stdint.h>

extern void md5x50_40(uint8_t * msg);
extern void md5x50_128(uint8_t * msg);

#endif /** __PDFCRACK_MD5_ */
