/*
 * This software is Copyright (c) 2024 magnum and it is hereby released to the
 * general public under the following terms:  Redistribution and use in source
 * and binary forms, with or without modification, are permitted.
 */
#ifndef OPENCL_HELPER_MACROS_H
#define OPENCL_HELPER_MACROS_H

#define CL_RO    CL_MEM_READ_ONLY
#define CL_WO    CL_MEM_WRITE_ONLY
#define CL_RW    CL_MEM_READ_WRITE
#define CL_ALLOC CL_MEM_ALLOC_HOST_PTR
#define CL_COPY  CL_MEM_COPY_HOST_PTR

/*
 * This creates a pinned (non pageable, can't be swapped) buffer, ensuring
 * fastest possible DMA transfer.  When not using pinned memory, an extra
 * step will happen in the background, where your (pageable) buffer is first
 * transfered to a temporary pinned buffer, then to GPU by means of DMA. When
 * your buffer is already using pinned memory, the extra step doesn't occur.
 *
 * It assumes you have defined three buffer variables with the same base
 * name. Example:
 *
 * unsigned char *data_blob;
 * cl_mem pinned_data_blob, cl_data_blob;
 * CLCREATEPINNED(data_blob, CL_RO, gws * some_size);
 * (...)
 * CLKERNELARG(crypt_kernel, 0, cl_data_blob);
 * (...)
 * CLWRITE(cl_data_blob, FALSE, 0, gws * some_size, data_blob, NULL);
 *
 * If the buffer can't be pinned, we silently fallback to a normal buffer.
 */
#define CLCREATEPINNED(var, flags, size)	  \
	do { \
		pinned_##var = clCreateBuffer(context[gpu_id], flags | CL_ALLOC, size, NULL, &ret_code); \
		if (ret_code != CL_SUCCESS) { \
			var = mem_alloc(size); \
			if (var == NULL) \
				HANDLE_CLERROR(ret_code, "Error allocating pinned buffer"); \
		} else { \
			var = clEnqueueMapBuffer(queue[gpu_id], pinned_##var, CL_TRUE, \
			                         CL_MAP_READ | CL_MAP_WRITE, 0, size, 0, NULL, NULL, &ret_code); \
			HANDLE_CLERROR(ret_code, "Error mapping buffer"); \
			cl_##var = clCreateBuffer(context[gpu_id], flags, size, NULL, &ret_code); \
			HANDLE_CLERROR(ret_code, "Error creating device buffer"); \
		} \
	} while(0)

#define CLCREATEBUFFER(var, flags, size)	  \
	do { var = clCreateBuffer(context[gpu_id], flags, size, NULL, &ret_code); \
		HANDLE_CLERROR(ret_code, "Error allocating GPU memory"); } while(0)

#define CLCREATEBUFCOPY(var, flags, size, _hostbuf)	  \
	do { var = clCreateBuffer(context[gpu_id], flags | CL_COPY, size, _hostbuf, &ret_code); \
		HANDLE_CLERROR(ret_code, "Error copying host pointer for GPU"); } while(0)

#define CLKERNELARG(kernel, id, arg)	  \
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), &arg), \
	               "Error setting kernel argument")

#define CLKRNARGLOC(kernel, id, arg)	  \
	HANDLE_CLERROR(clSetKernelArg(kernel, id, sizeof(arg), NULL), \
	               "Error setting kernel argument for local memory")

#define CLWRITE(gpu_var, wait, offset, size, host_var, event)	  \
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], gpu_var, wait, offset, size, host_var, 0, NULL, event), \
	               "Failed writing buffer")

#define CLWRITE_CRYPT(gpu_var, wait, offset, size, host_var, event)	  \
	BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], gpu_var, wait, offset, size, host_var, 0, NULL, event), \
	              "Failed writing buffer")

#define CLREAD_CRYPT(gpu_var, wait, offset, size, host_var, event)	  \
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], gpu_var, wait, offset, size, host_var, 0, NULL, event),\
	              "failed reading buffer")

#define RELEASEPINNED(var)	  \
	do { \
		if (pinned_##var) { \
			HANDLE_CLERROR(clEnqueueUnmapMemObject(queue[gpu_id], pinned_##var, var, 0, NULL, NULL), \
			               "Error Unmapping buffer"); \
			HANDLE_CLERROR(clFinish(queue[gpu_id]), "Error releasing memory mapping"); var = NULL; \
		} else \
			MEM_FREE(var); \
		HANDLE_CLERROR(clReleaseMemObject(pinned_##var), "Error releasing pinned buffer"); \
		pinned_##var = NULL; \
		HANDLE_CLERROR(clReleaseMemObject(cl_##var), "Error releasing buffer"); \
		cl_##var = NULL; \
	} while(0);

#define RELEASEBUFFER(var)	\
	do { HANDLE_CLERROR(clReleaseMemObject(var), "Release buffer"); var = NULL; } while(0)

#define CREATEKERNEL(kernel, name)	  \
	do { kernel = clCreateKernel(program[gpu_id], name, &ret_code); \
		HANDLE_CLERROR(ret_code, name); } while(0);

#endif	/* OPENCL_HELPER_MACROS_H */
