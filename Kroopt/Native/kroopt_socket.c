/*
 * kroopt_socket.c — test-only real-IO transport helpers (NOT kroopt core).
 *
 * A minimal AF_UNIX socketpair plus blocking read/write/close, so a test can run
 * the kroopt handshake over a real OS socket and confirm the records survive real
 * kernel I/O. kroopt's production core performs no syscalls and reaches the network
 * only through iotakt (RFC 010); this file exists purely to exercise the transport
 * boundary from a test. No protocol logic lives here — just byte movement.
 *
 * IO ABI mirrors kroopt_ffi.c's `kroopt_ffi_random`: a trailing `lean_object *w`
 * world token and a `lean_io_result_mk_ok(...)` return. ByteArray inputs are
 * borrowed, matching the crypto FFI.
 */
#include <lean/lean.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

/* IO: create an AF_UNIX SOCK_STREAM socketpair; pack the two fds into a UInt64
 * (fd0 high 32 bits, fd1 low 32 bits). 0xFFFF...F signals failure. */
LEAN_EXPORT lean_object *kroopt_socketpair(lean_object *w) {
  (void)w;
  int fds[2];
  uint64_t packed;
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
    packed = 0xFFFFFFFFFFFFFFFFULL;
  } else {
    packed = ((uint64_t)(uint32_t)fds[0] << 32) | (uint32_t)fds[1];
  }
  return lean_io_result_mk_ok(lean_box_uint64(packed));
}

/* IO: write all of `buf` to fd; returns bytes written. */
LEAN_EXPORT lean_object *kroopt_sock_write(uint32_t fd, b_lean_obj_arg buf, lean_object *w) {
  (void)w;
  size_t len = lean_sarray_size(buf);
  uint8_t *p = lean_sarray_cptr(buf);
  size_t sent = 0;
  while (sent < len) {
    ssize_t k = write((int)fd, p + sent, len - sent);
    if (k <= 0) break;
    sent += (size_t)k;
  }
  return lean_io_result_mk_ok(lean_box_uint64((uint64_t)sent));
}

/* IO: read up to `n` bytes from fd (blocking until n bytes or EOF); returns the
 * bytes actually read. */
LEAN_EXPORT lean_object *kroopt_sock_read(uint32_t fd, uint32_t n, lean_object *w) {
  (void)w;
  uint8_t *tmp = (uint8_t *)malloc(n ? n : 1);
  size_t got = 0;
  while (got < n) {
    ssize_t k = read((int)fd, tmp + got, (size_t)n - got);
    if (k <= 0) break;
    got += (size_t)k;
  }
  lean_object *r = lean_alloc_sarray(1, got, got);
  memcpy(lean_sarray_cptr(r), tmp, got);
  free(tmp);
  return lean_io_result_mk_ok(r);
}

/* IO: close an fd. */
LEAN_EXPORT lean_object *kroopt_sock_close(uint32_t fd, lean_object *w) {
  (void)w;
  close((int)fd);
  return lean_io_result_mk_ok(lean_box(0));
}

/* IO: bind+listen an AF_UNIX SOCK_STREAM socket at `path` (unlinking any stale
 * node first). Returns the listening fd (UInt32), or 0xFFFFFFFF on failure.
 * Test-only orchestration so a real client (OpenSSL/Python) can connect. */
LEAN_EXPORT lean_object *kroopt_sock_listen(b_lean_obj_arg path, lean_object *w) {
  (void)w;
  const char *p = lean_string_cstr(path);
  uint32_t result = 0xFFFFFFFFu;
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd >= 0) {
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, p, sizeof(addr.sun_path) - 1);
    unlink(p);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 && listen(fd, 1) == 0) {
      result = (uint32_t)fd;
    } else {
      close(fd);
    }
  }
  return lean_io_result_mk_ok(lean_box_uint32(result));
}

/* IO: accept one connection on a listening fd; returns the connection fd
 * (UInt32), or 0xFFFFFFFF on failure. Blocks until a client connects. */
LEAN_EXPORT lean_object *kroopt_sock_accept(uint32_t lfd, lean_object *w) {
  (void)w;
  int cfd = accept((int)lfd, NULL, NULL);
  uint32_t result = (cfd >= 0) ? (uint32_t)cfd : 0xFFFFFFFFu;
  return lean_io_result_mk_ok(lean_box_uint32(result));
}
