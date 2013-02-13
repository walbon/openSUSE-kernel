/* exynos_drm.h
 *
 * Copyright (c) 2011 Samsung Electronics Co., Ltd.
 * Authors:
 *	Inki Dae <inki.dae@samsung.com>
 *	Joonyoung Shim <jy0922.shim@samsung.com>
 *	Seung-Woo Kim <sw0312.kim@samsung.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _EXYNOS_DRM_H_
#define _EXYNOS_DRM_H_

#include <uapi/drm/exynos_drm.h>

#ifdef __KERNEL__

/**
 * A structure for lcd panel information.
 *
 * @timing: default video mode for initializing
 * @width_mm: physical size of lcd width.
 * @height_mm: physical size of lcd height.
 */
struct exynos_drm_panel_info {
	struct fb_videomode timing;
	u32 width_mm;
	u32 height_mm;
};

/**
 * Platform Specific Structure for DRM based FIMD.
 *
 * @panel: default panel info for initializing
 * @default_win: default window layer number to be used for UI.
 * @bpp: default bit per pixel.
 */
struct exynos_drm_fimd_pdata {
	struct exynos_drm_panel_info panel;
	u32				vidcon0;
	u32				vidcon1;
	unsigned int			default_win;
	unsigned int			bpp;
};

#endif	/* __KERNEL__ */
#endif	/* _EXYNOS_DRM_H_ */
