/*************************************************************************/ /*!
@Title          Hardware definition file rgx_bvnc_table_km.h
@Copyright      Copyright (c) Imagination Technologies Ltd. All Rights Reserved
@License        Dual MIT/GPLv2

The contents of this file are subject to the MIT license as set out below.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

Alternatively, the contents of this file may be used under the terms of
the GNU General Public License Version 2 ("GPL") in which case the provisions
of GPL are applicable instead of those above.

If you wish to allow use of your version of this file only under the terms of
GPL, and not to allow others to use your version of this file under the terms
of the MIT license, indicate your decision by deleting the provisions above
and replace them with the notice and other provisions required by GPL as set
out in the file called "GPL-COPYING" included in this distribution. If you do
not delete the provisions above, a recipient may use your version of this file
under the terms of either the MIT license or GPL.

This License is also included in this distribution in the file called
"MIT-COPYING".

EXCEPT AS OTHERWISE STATED IN A NEGOTIATED AGREEMENT: (A) THE SOFTWARE IS
PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT; AND (B) IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/ /**************************************************************************/

/******************************************************************************
 *                 Auto generated file by rgxbvnc_tablegen.py                 *
 *                  This file should not be edited manually                   *
 *****************************************************************************/

#ifndef RGX_BVNC_TABLE_KM_H
#define RGX_BVNC_TABLE_KM_H

#include "img_types.h"
#include "img_defs.h"
#include "rgxdefs_km.h"
#include "rgx_bvnc_defs_km.h"

#ifndef RGXBVNC_C
#error "This file should only be included from rgxbvnc.c"
#endif

#if defined(RGX_BVNC_TABLE_UM_H)
#error "This file should not be included in conjunction with rgx_bvnc_table_um.h"
#endif


/******************************************************************************
 * Arrays for each feature with values used
 * for handling the corresponding values
 *****************************************************************************/

static const IMG_UINT16 aui16_RGX_FEATURE_CDM_CONTROL_STREAM_FORMAT_values[RGX_FEATURE_CDM_CONTROL_STREAM_FORMAT_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 1, 2, };

static const IMG_UINT16 aui16_RGX_FEATURE_ECC_RAMS_values[RGX_FEATURE_ECC_RAMS_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 0, 2, };

static const IMG_UINT16 aui16_RGX_FEATURE_FBCDC_values[RGX_FEATURE_FBCDC_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 3, 4, 50, };

static const IMG_UINT16 aui16_RGX_FEATURE_FBCDC_ALGORITHM_values[RGX_FEATURE_FBCDC_ALGORITHM_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 1, 2, 3, 4, 50, };

static const IMG_UINT16 aui16_RGX_FEATURE_FBCDC_ARCHITECTURE_values[RGX_FEATURE_FBCDC_ARCHITECTURE_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 1, 2, 3, 7, };

static const IMG_UINT16 aui16_RGX_FEATURE_FBC_MAX_DEFAULT_DESCRIPTORS_values[RGX_FEATURE_FBC_MAX_DEFAULT_DESCRIPTORS_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 0, };

static const IMG_UINT16 aui16_RGX_FEATURE_FBC_MAX_LARGE_DESCRIPTORS_values[RGX_FEATURE_FBC_MAX_LARGE_DESCRIPTORS_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 0, };

static const IMG_UINT16 aui16_RGX_FEATURE_LAYOUT_MARS_values[RGX_FEATURE_LAYOUT_MARS_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 0, 1, };

static const IMG_UINT16 aui16_RGX_FEATURE_META_values[RGX_FEATURE_META_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, LTP217, LTP218, MTP218, MTP219, };

static const IMG_UINT16 aui16_RGX_FEATURE_META_COREMEM_BANKS_values[RGX_FEATURE_META_COREMEM_BANKS_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 8, };

static const IMG_UINT16 aui16_RGX_FEATURE_META_COREMEM_SIZE_values[RGX_FEATURE_META_COREMEM_SIZE_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 0, 32, 256, };

static const IMG_UINT16 aui16_RGX_FEATURE_META_DMA_CHANNEL_COUNT_values[RGX_FEATURE_META_DMA_CHANNEL_COUNT_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 4, };

static const IMG_UINT16 aui16_RGX_FEATURE_NUM_CLUSTERS_values[RGX_FEATURE_NUM_CLUSTERS_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 1, 2, 4, 6, };

static const IMG_UINT16 aui16_RGX_FEATURE_NUM_ISP_IPP_PIPES_values[RGX_FEATURE_NUM_ISP_IPP_PIPES_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 1, 2, 3, 4, 6, 7, 8, 12, };

static const IMG_UINT16 aui16_RGX_FEATURE_NUM_MEMBUS_values[RGX_FEATURE_NUM_MEMBUS_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 1, };

static const IMG_UINT16 aui16_RGX_FEATURE_NUM_OSIDS_values[RGX_FEATURE_NUM_OSIDS_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 2, 8, };

static const IMG_UINT16 aui16_RGX_FEATURE_NUM_RASTER_PIPES_values[RGX_FEATURE_NUM_RASTER_PIPES_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 0, 1, 2, };

static const IMG_UINT16 aui16_RGX_FEATURE_PHYS_BUS_WIDTH_values[RGX_FEATURE_PHYS_BUS_WIDTH_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 32, 36, 40, };

static const IMG_UINT16 aui16_RGX_FEATURE_SCALABLE_TE_ARCH_values[RGX_FEATURE_SCALABLE_TE_ARCH_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 1, };

static const IMG_UINT16 aui16_RGX_FEATURE_SCALABLE_VCE_values[RGX_FEATURE_SCALABLE_VCE_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 1, };

static const IMG_UINT16 aui16_RGX_FEATURE_SIMPLE_PARAMETER_FORMAT_VERSION_values[RGX_FEATURE_SIMPLE_PARAMETER_FORMAT_VERSION_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 1, 2, };

static const IMG_UINT16 aui16_RGX_FEATURE_SLC_BANKS_values[RGX_FEATURE_SLC_BANKS_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 1, 2, 4, };

static const IMG_UINT16 aui16_RGX_FEATURE_SLC_CACHE_LINE_SIZE_BITS_values[RGX_FEATURE_SLC_CACHE_LINE_SIZE_BITS_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 512, };

static const IMG_UINT16 aui16_RGX_FEATURE_SLC_SIZE_IN_KILOBYTES_values[RGX_FEATURE_SLC_SIZE_IN_KILOBYTES_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 2, 8, 16, 64, 128, 512, };

static const IMG_UINT16 aui16_RGX_FEATURE_TFBC_VERSION_values[RGX_FEATURE_TFBC_VERSION_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 10, 11, 20, };

static const IMG_UINT16 aui16_RGX_FEATURE_TILE_SIZE_X_values[RGX_FEATURE_TILE_SIZE_X_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 16, 32, };

static const IMG_UINT16 aui16_RGX_FEATURE_TILE_SIZE_Y_values[RGX_FEATURE_TILE_SIZE_Y_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 16, 32, };

static const IMG_UINT16 aui16_RGX_FEATURE_VIRTUAL_ADDRESS_SPACE_BITS_values[RGX_FEATURE_VIRTUAL_ADDRESS_SPACE_BITS_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 40, };

static const IMG_UINT16 aui16_RGX_FEATURE_XE_ARCHITECTURE_values[RGX_FEATURE_XE_ARCHITECTURE_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 1, };

static const IMG_UINT16 aui16_RGX_FEATURE_XPU_MAX_REGBANKS_ADDR_WIDTH_values[RGX_FEATURE_XPU_MAX_REGBANKS_ADDR_WIDTH_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 19, };

static const IMG_UINT16 aui16_RGX_FEATURE_XPU_MAX_SLAVES_values[RGX_FEATURE_XPU_MAX_SLAVES_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 2, 3, };

static const IMG_UINT16 aui16_RGX_FEATURE_XPU_REGISTER_BROADCAST_values[RGX_FEATURE_XPU_REGISTER_BROADCAST_MAX_VALUE_IDX] = {(IMG_UINT16)RGX_FEATURE_VALUE_DISABLED, 0, 1, };


/******************************************************************************
 * Table contains pointers to each feature value array for features that have
 * values.
 * Indexed using enum RGX_FEATURE_WITH_VALUE_INDEX from rgx_bvnc_defs_km.h
 *****************************************************************************/

static const void * const gaFeaturesValues[RGX_FEATURE_WITH_VALUES_MAX_IDX] = {
	aui16_RGX_FEATURE_CDM_CONTROL_STREAM_FORMAT_values,
	aui16_RGX_FEATURE_ECC_RAMS_values,
	aui16_RGX_FEATURE_FBCDC_values,
	aui16_RGX_FEATURE_FBCDC_ALGORITHM_values,
	aui16_RGX_FEATURE_FBCDC_ARCHITECTURE_values,
	aui16_RGX_FEATURE_FBC_MAX_DEFAULT_DESCRIPTORS_values,
	aui16_RGX_FEATURE_FBC_MAX_LARGE_DESCRIPTORS_values,
	aui16_RGX_FEATURE_LAYOUT_MARS_values,
	aui16_RGX_FEATURE_META_values,
	aui16_RGX_FEATURE_META_COREMEM_BANKS_values,
	aui16_RGX_FEATURE_META_COREMEM_SIZE_values,
	aui16_RGX_FEATURE_META_DMA_CHANNEL_COUNT_values,
	aui16_RGX_FEATURE_NUM_CLUSTERS_values,
	aui16_RGX_FEATURE_NUM_ISP_IPP_PIPES_values,
	aui16_RGX_FEATURE_NUM_MEMBUS_values,
	aui16_RGX_FEATURE_NUM_OSIDS_values,
	aui16_RGX_FEATURE_NUM_RASTER_PIPES_values,
	aui16_RGX_FEATURE_PHYS_BUS_WIDTH_values,
	aui16_RGX_FEATURE_SCALABLE_TE_ARCH_values,
	aui16_RGX_FEATURE_SCALABLE_VCE_values,
	aui16_RGX_FEATURE_SIMPLE_PARAMETER_FORMAT_VERSION_values,
	aui16_RGX_FEATURE_SLC_BANKS_values,
	aui16_RGX_FEATURE_SLC_CACHE_LINE_SIZE_BITS_values,
	aui16_RGX_FEATURE_SLC_SIZE_IN_KILOBYTES_values,
	aui16_RGX_FEATURE_TFBC_VERSION_values,
	aui16_RGX_FEATURE_TILE_SIZE_X_values,
	aui16_RGX_FEATURE_TILE_SIZE_Y_values,
	aui16_RGX_FEATURE_VIRTUAL_ADDRESS_SPACE_BITS_values,
	aui16_RGX_FEATURE_XE_ARCHITECTURE_values,
	aui16_RGX_FEATURE_XPU_MAX_REGBANKS_ADDR_WIDTH_values,
	aui16_RGX_FEATURE_XPU_MAX_SLAVES_values,
	aui16_RGX_FEATURE_XPU_REGISTER_BROADCAST_values,
};


/******************************************************************************
 * Array containing the lengths of the arrays containing the values.
 * Used for indexing the aui16_<FEATURE>_values defined upwards
 *****************************************************************************/


static const IMG_UINT16 gaFeaturesValuesMaxIndexes[] = {
	RGX_FEATURE_CDM_CONTROL_STREAM_FORMAT_MAX_VALUE_IDX,
	RGX_FEATURE_ECC_RAMS_MAX_VALUE_IDX,
	RGX_FEATURE_FBCDC_MAX_VALUE_IDX,
	RGX_FEATURE_FBCDC_ALGORITHM_MAX_VALUE_IDX,
	RGX_FEATURE_FBCDC_ARCHITECTURE_MAX_VALUE_IDX,
	RGX_FEATURE_FBC_MAX_DEFAULT_DESCRIPTORS_MAX_VALUE_IDX,
	RGX_FEATURE_FBC_MAX_LARGE_DESCRIPTORS_MAX_VALUE_IDX,
	RGX_FEATURE_LAYOUT_MARS_MAX_VALUE_IDX,
	RGX_FEATURE_META_MAX_VALUE_IDX,
	RGX_FEATURE_META_COREMEM_BANKS_MAX_VALUE_IDX,
	RGX_FEATURE_META_COREMEM_SIZE_MAX_VALUE_IDX,
	RGX_FEATURE_META_DMA_CHANNEL_COUNT_MAX_VALUE_IDX,
	RGX_FEATURE_NUM_CLUSTERS_MAX_VALUE_IDX,
	RGX_FEATURE_NUM_ISP_IPP_PIPES_MAX_VALUE_IDX,
	RGX_FEATURE_NUM_MEMBUS_MAX_VALUE_IDX,
	RGX_FEATURE_NUM_OSIDS_MAX_VALUE_IDX,
	RGX_FEATURE_NUM_RASTER_PIPES_MAX_VALUE_IDX,
	RGX_FEATURE_PHYS_BUS_WIDTH_MAX_VALUE_IDX,
	RGX_FEATURE_SCALABLE_TE_ARCH_MAX_VALUE_IDX,
	RGX_FEATURE_SCALABLE_VCE_MAX_VALUE_IDX,
	RGX_FEATURE_SIMPLE_PARAMETER_FORMAT_VERSION_MAX_VALUE_IDX,
	RGX_FEATURE_SLC_BANKS_MAX_VALUE_IDX,
	RGX_FEATURE_SLC_CACHE_LINE_SIZE_BITS_MAX_VALUE_IDX,
	RGX_FEATURE_SLC_SIZE_IN_KILOBYTES_MAX_VALUE_IDX,
	RGX_FEATURE_TFBC_VERSION_MAX_VALUE_IDX,
	RGX_FEATURE_TILE_SIZE_X_MAX_VALUE_IDX,
	RGX_FEATURE_TILE_SIZE_Y_MAX_VALUE_IDX,
	RGX_FEATURE_VIRTUAL_ADDRESS_SPACE_BITS_MAX_VALUE_IDX,
	RGX_FEATURE_XE_ARCHITECTURE_MAX_VALUE_IDX,
	RGX_FEATURE_XPU_MAX_REGBANKS_ADDR_WIDTH_MAX_VALUE_IDX,
	RGX_FEATURE_XPU_MAX_SLAVES_MAX_VALUE_IDX,
	RGX_FEATURE_XPU_REGISTER_BROADCAST_MAX_VALUE_IDX,
};

#define RGX_FEATURE_VALUE_TYPE_UINT16 (0x0000U)
#define RGX_FEATURE_VALUE_TYPE_UINT32 (0x8000U)
#define RGX_FEATURE_TYPE_BIT_SHIFT 14

/******************************************************************************
 * Bit-positions for features with values
 *****************************************************************************/

static const IMG_UINT16 aui16FeaturesWithValuesBitPositions[] = {
	(0U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_CDM_CONTROL_STREAM_FORMAT_POS */
	(2U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_ECC_RAMS_POS */
	(4U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_FBCDC_POS */
	(7U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_FBCDC_ALGORITHM_POS */
	(10U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_FBCDC_ARCHITECTURE_POS */
	(13U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_FBC_MAX_DEFAULT_DESCRIPTORS_POS */
	(15U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_FBC_MAX_LARGE_DESCRIPTORS_POS */
	(17U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_LAYOUT_MARS_POS */
	(19U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_META_POS */
	(22U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_META_COREMEM_BANKS_POS */
	(24U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_META_COREMEM_SIZE_POS */
	(27U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_META_DMA_CHANNEL_COUNT_POS */
	(29U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_NUM_CLUSTERS_POS */
	(32U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_NUM_ISP_IPP_PIPES_POS */
	(36U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_NUM_MEMBUS_POS */
	(38U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_NUM_OSIDS_POS */
	(40U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_NUM_RASTER_PIPES_POS */
	(43U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_PHYS_BUS_WIDTH_POS */
	(46U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_SCALABLE_TE_ARCH_POS */
	(48U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_SCALABLE_VCE_POS */
	(50U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_SIMPLE_PARAMETER_FORMAT_VERSION_POS */
	(52U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_SLC_BANKS_POS */
	(55U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_SLC_CACHE_LINE_SIZE_BITS_POS */
	(57U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_SLC_SIZE_IN_KILOBYTES_POS */
	(60U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_TFBC_VERSION_POS */
	(64U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_TILE_SIZE_X_POS */
	(66U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_TILE_SIZE_Y_POS */
	(68U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_VIRTUAL_ADDRESS_SPACE_BITS_POS */
	(70U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_XE_ARCHITECTURE_POS */
	(72U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_XPU_MAX_REGBANKS_ADDR_WIDTH_POS */
	(74U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_XPU_MAX_SLAVES_POS */
	(76U) | RGX_FEATURE_VALUE_TYPE_UINT16, /* RGX_FEATURE_XPU_REGISTER_BROADCAST_POS */
};


/******************************************************************************
 * Bit-masks for features with values
 *****************************************************************************/

static const IMG_UINT64 aui64FeaturesWithValuesBitMasks[] = {
	(IMG_UINT64_C(0x0000000000000003)), /* RGX_FEATURE_CDM_CONTROL_STREAM_FORMAT_BIT_MASK */
	(IMG_UINT64_C(0x000000000000000C)), /* RGX_FEATURE_ECC_RAMS_BIT_MASK */
	(IMG_UINT64_C(0x0000000000000070)), /* RGX_FEATURE_FBCDC_BIT_MASK */
	(IMG_UINT64_C(0x0000000000000380)), /* RGX_FEATURE_FBCDC_ALGORITHM_BIT_MASK */
	(IMG_UINT64_C(0x0000000000001C00)), /* RGX_FEATURE_FBCDC_ARCHITECTURE_BIT_MASK */
	(IMG_UINT64_C(0x0000000000006000)), /* RGX_FEATURE_FBC_MAX_DEFAULT_DESCRIPTORS_BIT_MASK */
	(IMG_UINT64_C(0x0000000000018000)), /* RGX_FEATURE_FBC_MAX_LARGE_DESCRIPTORS_BIT_MASK */
	(IMG_UINT64_C(0x0000000000060000)), /* RGX_FEATURE_LAYOUT_MARS_BIT_MASK */
	(IMG_UINT64_C(0x0000000000380000)), /* RGX_FEATURE_META_BIT_MASK */
	(IMG_UINT64_C(0x0000000000C00000)), /* RGX_FEATURE_META_COREMEM_BANKS_BIT_MASK */
	(IMG_UINT64_C(0x0000000007000000)), /* RGX_FEATURE_META_COREMEM_SIZE_BIT_MASK */
	(IMG_UINT64_C(0x0000000018000000)), /* RGX_FEATURE_META_DMA_CHANNEL_COUNT_BIT_MASK */
	(IMG_UINT64_C(0x00000000E0000000)), /* RGX_FEATURE_NUM_CLUSTERS_BIT_MASK */
	(IMG_UINT64_C(0x0000000F00000000)), /* RGX_FEATURE_NUM_ISP_IPP_PIPES_BIT_MASK */
	(IMG_UINT64_C(0x0000003000000000)), /* RGX_FEATURE_NUM_MEMBUS_BIT_MASK */
	(IMG_UINT64_C(0x000000C000000000)), /* RGX_FEATURE_NUM_OSIDS_BIT_MASK */
	(IMG_UINT64_C(0x0000070000000000)), /* RGX_FEATURE_NUM_RASTER_PIPES_BIT_MASK */
	(IMG_UINT64_C(0x0000380000000000)), /* RGX_FEATURE_PHYS_BUS_WIDTH_BIT_MASK */
	(IMG_UINT64_C(0x0000C00000000000)), /* RGX_FEATURE_SCALABLE_TE_ARCH_BIT_MASK */
	(IMG_UINT64_C(0x0003000000000000)), /* RGX_FEATURE_SCALABLE_VCE_BIT_MASK */
	(IMG_UINT64_C(0x000C000000000000)), /* RGX_FEATURE_SIMPLE_PARAMETER_FORMAT_VERSION_BIT_MASK */
	(IMG_UINT64_C(0x0070000000000000)), /* RGX_FEATURE_SLC_BANKS_BIT_MASK */
	(IMG_UINT64_C(0x0180000000000000)), /* RGX_FEATURE_SLC_CACHE_LINE_SIZE_BITS_BIT_MASK */
	(IMG_UINT64_C(0x0E00000000000000)), /* RGX_FEATURE_SLC_SIZE_IN_KILOBYTES_BIT_MASK */
	(IMG_UINT64_C(0x7000000000000000)), /* RGX_FEATURE_TFBC_VERSION_BIT_MASK */
	(IMG_UINT64_C(0x0000000000000003)), /* RGX_FEATURE_TILE_SIZE_X_BIT_MASK */
	(IMG_UINT64_C(0x000000000000000C)), /* RGX_FEATURE_TILE_SIZE_Y_BIT_MASK */
	(IMG_UINT64_C(0x0000000000000030)), /* RGX_FEATURE_VIRTUAL_ADDRESS_SPACE_BITS_BIT_MASK */
	(IMG_UINT64_C(0x00000000000000C0)), /* RGX_FEATURE_XE_ARCHITECTURE_BIT_MASK */
	(IMG_UINT64_C(0x0000000000000300)), /* RGX_FEATURE_XPU_MAX_REGBANKS_ADDR_WIDTH_BIT_MASK */
	(IMG_UINT64_C(0x0000000000000C00)), /* RGX_FEATURE_XPU_MAX_SLAVES_BIT_MASK */
	(IMG_UINT64_C(0x0000000000003000)), /* RGX_FEATURE_XPU_REGISTER_BROADCAST_BIT_MASK */
};


/******************************************************************************
 * Table mapping bitmasks for features and features with values
 *****************************************************************************/


static const IMG_UINT64 gaFeatures[][4]=
{
	{ IMG_UINT64_C(0x000100000002001e), IMG_UINT64_C(0x0000400000402025), IMG_UINT64_C(0x0a801a03411aa481), IMG_UINT64_C(0x000000000000001a) },	/* 1.0.2.30 */
	{ IMG_UINT64_C(0x0001000000040005), IMG_UINT64_C(0x0000400000402024), IMG_UINT64_C(0x0a801a03611aa481), IMG_UINT64_C(0x000000000000001a) },	/* 1.0.4.5 */
	{ IMG_UINT64_C(0x0001000000040013), IMG_UINT64_C(0x0000400000402025), IMG_UINT64_C(0x0a801a03611aa481), IMG_UINT64_C(0x000000000000001a) },	/* 1.0.4.19 */
	{ IMG_UINT64_C(0x0004000000020033), IMG_UINT64_C(0x0102c04000c0222f), IMG_UINT64_C(0x0a801a074212a901), IMG_UINT64_C(0x000000000000001a) },	/* 4.0.2.51 */
	{ IMG_UINT64_C(0x000400000002003a), IMG_UINT64_C(0x0102c04000c0322f), IMG_UINT64_C(0x0a801a874212a901), IMG_UINT64_C(0x000000000000001a) },	/* 4.0.2.58 */
	{ IMG_UINT64_C(0x0004000000040037), IMG_UINT64_C(0x0102c04000c0222e), IMG_UINT64_C(0x0a801a076212a901), IMG_UINT64_C(0x000000000000001a) },	/* 4.0.4.55 */
	{ IMG_UINT64_C(0x000400000006003e), IMG_UINT64_C(0x0102c04000c0322f), IMG_UINT64_C(0x0ab01b878212a901), IMG_UINT64_C(0x000000000000001a) },	/* 4.0.6.62 */
	{ IMG_UINT64_C(0x000500000001002e), IMG_UINT64_C(0x0000004004402205), IMG_UINT64_C(0x06901a01210aa501), IMG_UINT64_C(0x000000000000005a) },	/* 5.0.1.46 */
	{ IMG_UINT64_C(0x0006000000040023), IMG_UINT64_C(0x0102c04000c0222f), IMG_UINT64_C(0x0a801a076212a901), IMG_UINT64_C(0x000000000000001a) },	/* 6.0.4.35 */
	{ IMG_UINT64_C(0x000f000000010040), IMG_UINT64_C(0x0000004004403205), IMG_UINT64_C(0x08901a82210aa501), IMG_UINT64_C(0x000000000000005a) },	/* 15.0.1.64 */
	{ IMG_UINT64_C(0x0016000000150010), IMG_UINT64_C(0x000000c5844b3025), IMG_UINT64_C(0x04940a8220020001), IMG_UINT64_C(0x0000000000000055) },	/* 22.0.21.16 */
	{ IMG_UINT64_C(0x0016000000360019), IMG_UINT64_C(0x000000c5844b3025), IMG_UINT64_C(0x08940a8320020001), IMG_UINT64_C(0x0000000000000055) },	/* 22.0.54.25 */
	{ IMG_UINT64_C(0x001600000036001e), IMG_UINT64_C(0x000000c5844b3025), IMG_UINT64_C(0x08940a8420020001), IMG_UINT64_C(0x0000000000000055) },	/* 22.0.54.30 */
	{ IMG_UINT64_C(0x0016000000360026), IMG_UINT64_C(0x000000c5844b3025), IMG_UINT64_C(0x0894128420020001), IMG_UINT64_C(0x0000000000000055) },	/* 22.0.54.38 */
	{ IMG_UINT64_C(0x001600000036014a), IMG_UINT64_C(0x000000c5844b3025), IMG_UINT64_C(0x08940a842002a591), IMG_UINT64_C(0x0000000000000055) },	/* 22.0.54.330 */
	{ IMG_UINT64_C(0x0016000000680012), IMG_UINT64_C(0x000000c5844b3025), IMG_UINT64_C(0x0894128620020001), IMG_UINT64_C(0x0000000000000055) },	/* 22.0.104.18 */
	{ IMG_UINT64_C(0x00160000006800da), IMG_UINT64_C(0x000000c5844b3025), IMG_UINT64_C(0x089412862002a591), IMG_UINT64_C(0x0000000000000055) },	/* 22.0.104.218 */
	{ IMG_UINT64_C(0x0016000000d0013e), IMG_UINT64_C(0x000000c5844b3025), IMG_UINT64_C(0x08a413884002a591), IMG_UINT64_C(0x0000000000000055) },	/* 22.0.208.318 */
	{ IMG_UINT64_C(0x00180000003600cc), IMG_UINT64_C(0x008001c2844f7425), IMG_UINT64_C(0x089812842002a591), IMG_UINT64_C(0x0000000000000055) },	/* 24.0.54.204 */
	{ IMG_UINT64_C(0x00180000006801f8), IMG_UINT64_C(0x008001c2844f7425), IMG_UINT64_C(0x089812852002a591), IMG_UINT64_C(0x0000000000000055) },	/* 24.0.104.504 */
	{ IMG_UINT64_C(0x0018000000d001f8), IMG_UINT64_C(0x008001c2844f7425), IMG_UINT64_C(0x0aa813884002a591), IMG_UINT64_C(0x0000000000000055) },	/* 24.0.208.504 */
	{ IMG_UINT64_C(0x0018000000d001f9), IMG_UINT64_C(0x008001c2844f7425), IMG_UINT64_C(0x0aa813884002a591), IMG_UINT64_C(0x0000000000000055) },	/* 24.0.208.505 */
	{ IMG_UINT64_C(0x001d0000003400ca), IMG_UINT64_C(0x008181c2844f74a5), IMG_UINT64_C(0x069812822002a621), IMG_UINT64_C(0x0000000000000055) },	/* 29.0.52.202 */
	{ IMG_UINT64_C(0x001d0000006c00d0), IMG_UINT64_C(0x008181c2844f74a5), IMG_UINT64_C(0x0aa813874002a621), IMG_UINT64_C(0x0000000000000055) },	/* 29.0.108.208 */
	{ IMG_UINT64_C(0x00210000000b0003), IMG_UINT64_C(0x00800092844b5085), IMG_UINT64_C(0x0298124120020001), IMG_UINT64_C(0x0000000000000055) },	/* 33.0.11.3 */
	{ IMG_UINT64_C(0x0021000000160001), IMG_UINT64_C(0x008180c2854b70a5), IMG_UINT64_C(0x0698128220020001), IMG_UINT64_C(0x0000000000000055) },	/* 33.0.22.1 */
	{ IMG_UINT64_C(0x00240000003400b6), IMG_UINT64_C(0x008000d2844b78a5), IMG_UINT64_C(0x169812822004b2b1), IMG_UINT64_C(0x0000000000002955) },	/* 36.0.52.182 */
	{ IMG_UINT64_C(0x0024000000360067), IMG_UINT64_C(0x008180d2844b38a5), IMG_UINT64_C(0x169812842002b2b1), IMG_UINT64_C(0x0000000000000055) },	/* 36.0.54.103 */
	{ IMG_UINT64_C(0x00240000003600b6), IMG_UINT64_C(0x008180d2844b78a5), IMG_UINT64_C(0x169812842004b2b1), IMG_UINT64_C(0x0000000000002955) },	/* 36.0.54.182 */
	{ IMG_UINT64_C(0x00240000003600b7), IMG_UINT64_C(0x008180d2844b78a5), IMG_UINT64_C(0x169812842004b2b1), IMG_UINT64_C(0x0000000000002955) },	/* 36.0.54.183 */
	{ IMG_UINT64_C(0x0024000000360118), IMG_UINT64_C(0x00819cd2844b78a5), IMG_UINT64_C(0x269812842004b2b1), IMG_UINT64_C(0x0000000000002955) },	/* 36.0.54.280 */
	{ IMG_UINT64_C(0x00240000006800b6), IMG_UINT64_C(0x008180d2844b78a5), IMG_UINT64_C(0x169812852004b2b1), IMG_UINT64_C(0x0000000000002955) },	/* 36.0.104.182 */
	{ IMG_UINT64_C(0x00240000006800b7), IMG_UINT64_C(0x008180d2844b78a5), IMG_UINT64_C(0x169812852004b2b1), IMG_UINT64_C(0x0000000000002955) },	/* 36.0.104.183 */
	{ IMG_UINT64_C(0x002400000068031c), IMG_UINT64_C(0x00e1a0d2864a78a5), IMG_UINT64_C(0x169812852004b2b9), IMG_UINT64_C(0x0000000000002955) },	/* 36.0.104.796 */
	{ IMG_UINT64_C(0x002e000000660185), IMG_UINT64_C(0x00901cd2844b78a5), IMG_UINT64_C(0x389812922004b2b5), IMG_UINT64_C(0x0000000000002955) },	/* 46.0.102.389 */
};

/******************************************************************************
 * Table mapping bitmasks for ERNs/BRNs
 *****************************************************************************/


static const IMG_UINT64 gaErnsBrns[][2]=
{
	{ IMG_UINT64_C(0x0001002700040013), IMG_UINT64_C(0x0000000000000005) },	/* 1.39.4.19 */
	{ IMG_UINT64_C(0x0001004b0002001e), IMG_UINT64_C(0x0000000000000004) },	/* 1.75.2.30 */
	{ IMG_UINT64_C(0x0001005200040005), IMG_UINT64_C(0x0000000000000000) },	/* 1.82.4.5 */
	{ IMG_UINT64_C(0x0004001f00040037), IMG_UINT64_C(0x000000000000108a) },	/* 4.31.4.55 */
	{ IMG_UINT64_C(0x0004002800020033), IMG_UINT64_C(0x000000000000108a) },	/* 4.40.2.51 */
	{ IMG_UINT64_C(0x0004002b0006003e), IMG_UINT64_C(0x000000000000508a) },	/* 4.43.6.62 */
	{ IMG_UINT64_C(0x0004002d0002003a), IMG_UINT64_C(0x000000000000500a) },	/* 4.45.2.58 */
	{ IMG_UINT64_C(0x0004002e0006003e), IMG_UINT64_C(0x000000000000508a) },	/* 4.46.6.62 */
	{ IMG_UINT64_C(0x000500090001002e), IMG_UINT64_C(0x0000000000000001) },	/* 5.9.1.46 */
	{ IMG_UINT64_C(0x0006002200040023), IMG_UINT64_C(0x000000000000100a) },	/* 6.34.4.35 */
	{ IMG_UINT64_C(0x000f000500010040), IMG_UINT64_C(0x0000000000004008) },	/* 15.5.1.64 */
	{ IMG_UINT64_C(0x0016001e00360019), IMG_UINT64_C(0x0000000000116b08) },	/* 22.30.54.25 */
	{ IMG_UINT64_C(0x001600280036001e), IMG_UINT64_C(0x0000000000116b08) },	/* 22.40.54.30 */
	{ IMG_UINT64_C(0x0016002e0036014a), IMG_UINT64_C(0x000000000011ea0a) },	/* 22.46.54.330 */
	{ IMG_UINT64_C(0x0016003100150010), IMG_UINT64_C(0x0000000000116b08) },	/* 22.49.21.16 */
	{ IMG_UINT64_C(0x001600430036001e), IMG_UINT64_C(0x0000000000116708) },	/* 22.67.54.30 */
	{ IMG_UINT64_C(0x001600440036001e), IMG_UINT64_C(0x0000000000116508) },	/* 22.68.54.30 */
	{ IMG_UINT64_C(0x00160056006800da), IMG_UINT64_C(0x000000000010e408) },	/* 22.86.104.218 */
	{ IMG_UINT64_C(0x0016005700680012), IMG_UINT64_C(0x0000000000106508) },	/* 22.87.104.18 */
	{ IMG_UINT64_C(0x0016006600360026), IMG_UINT64_C(0x0000000000106508) },	/* 22.102.54.38 */
	{ IMG_UINT64_C(0x0016006800d0013e), IMG_UINT64_C(0x000000000010e40a) },	/* 22.104.208.318 */
	{ IMG_UINT64_C(0x0016006900d0013e), IMG_UINT64_C(0x000000000010e40a) },	/* 22.105.208.318 */
	{ IMG_UINT64_C(0x0018003200d001f8), IMG_UINT64_C(0x000000000012210a) },	/* 24.50.208.504 */
	{ IMG_UINT64_C(0x0018003800d001f9), IMG_UINT64_C(0x000000000012210a) },	/* 24.56.208.505 */
	{ IMG_UINT64_C(0x00180042003600cc), IMG_UINT64_C(0x000000000012210a) },	/* 24.66.54.204 */
	{ IMG_UINT64_C(0x00180043006801f8), IMG_UINT64_C(0x000000000012210a) },	/* 24.67.104.504 */
	{ IMG_UINT64_C(0x001d000e006c00d0), IMG_UINT64_C(0x00000000001a212a) },	/* 29.14.108.208 */
	{ IMG_UINT64_C(0x001d0013003400ca), IMG_UINT64_C(0x00000000001a212a) },	/* 29.19.52.202 */
	{ IMG_UINT64_C(0x0021000800160001), IMG_UINT64_C(0x000000000010212a) },	/* 33.8.22.1 */
	{ IMG_UINT64_C(0x0021000f000b0003), IMG_UINT64_C(0x000000000010212a) },	/* 33.15.11.3 */
	{ IMG_UINT64_C(0x0024001d003400b6), IMG_UINT64_C(0x000000000010212a) },	/* 36.29.52.182 */
	{ IMG_UINT64_C(0x00240032003600b6), IMG_UINT64_C(0x000000000010212a) },	/* 36.50.54.182 */
	{ IMG_UINT64_C(0x00240034006800b6), IMG_UINT64_C(0x000000000010212a) },	/* 36.52.104.182 */
	{ IMG_UINT64_C(0x002400350068031c), IMG_UINT64_C(0x000000000010012a) },	/* 36.53.104.796 */
	{ IMG_UINT64_C(0x00240036003600b7), IMG_UINT64_C(0x000000000010212a) },	/* 36.54.54.183 */
	{ IMG_UINT64_C(0x0024003700360067), IMG_UINT64_C(0x000000000010212a) },	/* 36.55.54.103 */
	{ IMG_UINT64_C(0x00240038006800b7), IMG_UINT64_C(0x000000000010212a) },	/* 36.56.104.183 */
	{ IMG_UINT64_C(0x0024003c00360118), IMG_UINT64_C(0x000000000010212a) },	/* 36.60.54.280 */
	{ IMG_UINT64_C(0x002e004800660185), IMG_UINT64_C(0x000000000014212a) },	/* 46.72.102.389 */
};

#if defined(DEBUG)

#define FEATURE_NO_VALUES_NAMES_MAX_IDX (57U)

static const IMG_CHAR * const gaszFeaturesNoValuesNames[FEATURE_NO_VALUES_NAMES_MAX_IDX] =
{
	"AXI_ACELITE",
	"CLUSTER_GROUPING",
	"COMPUTE",
	"COMPUTE_MORTON_CAPABLE",
	"COMPUTE_ONLY",
	"COMPUTE_OVERLAP",
	"COMPUTE_OVERLAP_WITH_BARRIERS",
	"COREID_PER_OS",
	"DUST_POWER_ISLAND_S7",
	"DYNAMIC_DUST_POWER",
	"FASTRENDER_DM",
	"GPU_MULTICORE_SUPPORT",
	"GPU_VIRTUALISATION",
	"GS_RTA_SUPPORT",
	"IRQ_PER_OS",
	"META_DMA",
	"MIPS",
	"PBE2_IN_XE",
	"PBE_CHECKSUM_2D",
	"PBVNC_COREID_REG",
	"PDS_PER_DUST",
	"PDS_TEMPSIZE8",
	"PERFBUS",
	"PERF_COUNTER_BATCH",
	"PM_MMU_VFP",
	"RISCV_FW_PROCESSOR",
	"ROGUEXE",
	"S7_CACHE_HIERARCHY",
	"S7_TOP_INFRASTRUCTURE",
	"SCALABLE_VDM_GPP",
	"SIGNAL_SNOOPING",
	"SIMPLE_INTERNAL_PARAMETER_FORMAT",
	"SIMPLE_INTERNAL_PARAMETER_FORMAT_V1",
	"SIMPLE_INTERNAL_PARAMETER_FORMAT_V2",
	"SINGLE_BIF",
	"SLC_HYBRID_CACHELINE_64_128",
	"SLC_SIZE_CONFIGURABLE",
	"SLC_VIVT",
	"SOC_TIMER",
	"SYS_BUS_SECURE_RESET",
	"TDM_PDS_CHECKSUM",
	"TESSELLATION",
	"TFBC_DELTA_CORRELATION",
	"TFBC_LOSSY_37_PERCENT",
	"TFBC_NATIVE_YUV10",
	"TILE_REGION_PROTECTION",
	"TLA",
	"TPU_CEM_DATAMASTER_GLOBAL_REGISTERS",
	"TPU_DM_GLOBAL_REGISTERS",
	"TPU_FILTERING_MODE_CONTROL",
	"VDM_DRAWINDIRECT",
	"VDM_OBJECT_LEVEL_LLS",
	"VOLCANIC_TB",
	"WATCHDOG_TIMER",
	"WORKGROUP_PROTECTION",
	"XE_MEMORY_HIERARCHY",
	"XT_TOP_INFRASTRUCTURE",
};

#define ERNSBRNS_IDS_MAX_IDX (22U)

static const IMG_UINT32 gaui64ErnsBrnsIDs[ERNSBRNS_IDS_MAX_IDX] =
{
	38344,
	42290,
	42321,
	42606,
	46066,
	47025,
	50539,
	50767,
	57596,
	60084,
	61389,
	61450,
	63142,
	63553,
	64502,
	65101,
	65273,
	66622,
	66927,
	68186,
	71317,
	73472,
};

#endif /* defined(DEBUG) */
#endif /* RGX_BVNC_TABLE_KM_H */
