#pragma once
#include <stdint.h>

/* A DRM RENDER NODE (M2347).
 *
 * `/dev/dri/renderD128` is how every GL driver on Linux reaches a GPU: open
 * the node, ask who it is, ask what it can do, then create contexts and
 * submit command streams. Mesa's virgl driver is the caller we care about --
 * it turns GL into a virgl command stream and hands it to the kernel, which
 * forwards it to virtio-gpu, which hands it to virglrenderer on the host.
 *
 * The kernel understands none of the command stream, and that is the design,
 * not a shortcut: virgl's encoding is Mesa's business on one end and
 * virglrenderer's on the other. What the kernel owns is the boundary --
 * validating every user pointer, owning the handle namespace, and being
 * honest about which request it could not serve.
 *
 * Deliberately RENDER-only: no modesetting, no scanout, no dumb buffers. The
 * display is the compositor's and stays on the linear framebuffer. */

int  drm_is_node_path(const char *path);   /* 1 for /dev/dri/renderD128 (and card0) */
long drm_ioctl(int fd, unsigned long req, void *uarg);
int  drm_open_node(void);                  /* returns a node id, or -1 */
void drm_close_node(int id);

/* For app.c's mmap of a render-node descriptor: which physical frame backs
 * page `page` of the object named by VIRTGPU_MAP offset `off`, and how large
 * that object is. The handle namespace has exactly one owner (drm.c) and this
 * is how the mapping code asks it questions. (M2349) */
uint64_t drm_map_frame(uint64_t off, uint64_t page);
uint64_t drm_map_size(uint64_t off);

/* PRIME: name a DRM buffer object with a descriptor and get it back (M2362).
 * Implemented in app.c because it needs the process fd table. */
int app_drm_prime_fd(uint32_t bo_handle);    /* a new fd naming that object, or -1 */
int app_drm_prime_handle_of(int fd);         /* the object a prime fd names, or -1 */
