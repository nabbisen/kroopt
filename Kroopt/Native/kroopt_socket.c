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

/* ---- Non-blocking variants for the readiness-driven reactor (RFC 010 §6) ---- */
#include <fcntl.h>
#include <errno.h>
#include <poll.h>

/* IO: set O_NONBLOCK on an fd. */
LEAN_EXPORT lean_object *kroopt_sock_set_nonblocking(uint32_t fd, lean_object *w) {
  (void)w;
  int flags = fcntl((int)fd, F_GETFL, 0);
  if (flags >= 0) fcntl((int)fd, F_SETFL, flags | O_NONBLOCK);
  return lean_io_result_mk_ok(lean_box(0));
}

/* IO: one non-blocking recv() call. Returns a status-prefixed ByteArray:
 *   byte 0 = status: 0 = data follows, 1 = wouldBlock, 2 = eof, 3 = error
 *   bytes 1.. = the data read (only for status 0).
 * A single read() — partial records are reassembled by the core, not here. */
LEAN_EXPORT lean_object *kroopt_sock_recv_nb(uint32_t fd, uint32_t n, lean_object *w) {
  (void)w;
  size_t cap = n ? n : 1;
  uint8_t *tmp = (uint8_t *)malloc(cap + 1);
  ssize_t k = read((int)fd, tmp + 1, cap);
  uint8_t status;
  size_t outlen;
  if (k > 0)        { status = 0; outlen = (size_t)k; }
  else if (k == 0)  { status = 2; outlen = 0; }
  else if (errno == EAGAIN || errno == EWOULDBLOCK) { status = 1; outlen = 0; }
  else              { status = 3; outlen = 0; }
  tmp[0] = status;
  lean_object *r = lean_alloc_sarray(1, outlen + 1, outlen + 1);
  memcpy(lean_sarray_cptr(r), tmp, outlen + 1);
  free(tmp);
  return lean_io_result_mk_ok(r);
}

/* IO: one non-blocking send() call. Returns bytes accepted (UInt64); a non-empty
 * buffer returning 0 means wouldBlock; 0xFFFF...F signals a fatal error. */
LEAN_EXPORT lean_object *kroopt_sock_send_nb(uint32_t fd, b_lean_obj_arg buf, lean_object *w) {
  (void)w;
  size_t len = lean_sarray_size(buf);
  uint8_t *p = lean_sarray_cptr(buf);
  uint64_t result;
  if (len == 0) { result = 0; }
  else {
    ssize_t k = write((int)fd, p, len);
    if (k >= 0) result = (uint64_t)k;
    else if (errno == EAGAIN || errno == EWOULDBLOCK) result = 0;
    else result = 0xFFFFFFFFFFFFFFFFULL;
  }
  return lean_io_result_mk_ok(lean_box_uint64(result));
}

/* IO: poll an fd. Always waits for readable; also waits for writable when
 * wantWrite != 0. Returns a bitmask: 1 = readable, 2 = writable, 0 = timeout. */
LEAN_EXPORT lean_object *kroopt_sock_poll(uint32_t fd, uint8_t wantWrite, uint32_t timeoutMs, lean_object *w) {
  (void)w;
  struct pollfd pfd;
  pfd.fd = (int)fd;
  pfd.events = POLLIN | (wantWrite ? POLLOUT : 0);
  pfd.revents = 0;
  int rc = poll(&pfd, 1, (int)timeoutMs);
  uint32_t mask = 0;
  if (rc > 0) {
    if (pfd.revents & (POLLIN | POLLHUP | POLLERR)) mask |= 1;
    if (pfd.revents & POLLOUT) mask |= 2;
  }
  return lean_io_result_mk_ok(lean_box_uint32(mask));
}
