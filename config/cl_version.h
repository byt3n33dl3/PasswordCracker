#ifndef __CL_VERSION_H
#define __CL_VERSION_H

/* Detect which version to target */
#if !defined(CL_TARGET_OPENCL_VERSION)
#pragma message("cl_version.h: CL_TARGET_OPENCL_VERSION is not defined. Defaulting to 300 (OpenCL 3.0)")
#define CL_TARGET_OPENCL_VERSION 300
#endif
#if CL_TARGET_OPENCL_VERSION != 100 && \
    CL_TARGET_OPENCL_VERSION != 110 && \
    CL_TARGET_OPENCL_VERSION != 120 && \
    CL_TARGET_OPENCL_VERSION != 200 && \
    CL_TARGET_OPENCL_VERSION != 210 && \
    CL_TARGET_OPENCL_VERSION != 220 && \
    CL_TARGET_OPENCL_VERSION != 230 && \
    CL_TARGET_OPENCL_VERSION != 240 && \
    CL_TARGET_OPENCL_VERSION != 300
#pragma message("cl_version: CL_TARGET_OPENCL_VERSION is not a valid value (100, 110, 120, 200, 210, 220, 300). Defaulting to 300 (OpenCL 3.0)")
#undef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 300
#endif


/* OpenCL Version */
#if CL_TARGET_OPENCL_VERSION >= 300 && !defined(CL_VERSION_3_0)
#define CL_VERSION_3_0  1
#endif
#if CL_TARGET_OPENCL_VERSION >= 220 && !defined(CL_VERSION_2_2)
#define CL_VERSION_2_2  1
#endif
#if CL_TARGET_OPENCL_VERSION >= 210 && !defined(CL_VERSION_2_1)
#define CL_VERSION_2_1  1
#endif
#if CL_TARGET_OPENCL_VERSION >= 200 && !defined(CL_VERSION_2_0)
#define CL_VERSION_2_0  1
#endif
#if CL_TARGET_OPENCL_VERSION >= 120 && !defined(CL_VERSION_1_2)
#define CL_VERSION_1_2  1
#endif
#if CL_TARGET_OPENCL_VERSION >= 110 && !defined(CL_VERSION_1_1)
#define CL_VERSION_1_1  1
#endif
#if CL_TARGET_OPENCL_VERSION >= 100 && !defined(CL_VERSION_1_0)
#define CL_VERSION_1_0  1
#endif

/* Allow deprecated APIs for older OpenCL versions. */
#if CL_TARGET_OPENCL_VERSION <= 220 && !defined(CL_USE_DEPRECATED_OPENCL_2_2_APIS)
#define CL_USE_DEPRECATED_OPENCL_2_2_APIS
#endif
#if CL_TARGET_OPENCL_VERSION <= 210 && !defined(CL_USE_DEPRECATED_OPENCL_2_1_APIS)
#define CL_USE_DEPRECATED_OPENCL_2_1_APIS
#endif
#if CL_TARGET_OPENCL_VERSION <= 200 && !defined(CL_USE_DEPRECATED_OPENCL_2_0_APIS)
#define CL_USE_DEPRECATED_OPENCL_2_0_APIS
#endif
#if CL_TARGET_OPENCL_VERSION <= 120 && !defined(CL_USE_DEPRECATED_OPENCL_1_2_APIS)
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#endif
#if CL_TARGET_OPENCL_VERSION <= 110 && !defined(CL_USE_DEPRECATED_OPENCL_1_1_APIS)
#define CL_USE_DEPRECATED_OPENCL_1_1_APIS
#endif
#if CL_TARGET_OPENCL_VERSION <= 100 && !defined(CL_USE_DEPRECATED_OPENCL_1_0_APIS)
#define CL_USE_DEPRECATED_OPENCL_1_0_APIS
#endif

#endif  /* __CL_VERSION_H */

/*******************************************************************************
 * Copyright (c) 2018-2020 The Khronos Group Inc.
 * pexsouger configurations
 ******************************************************************************/
